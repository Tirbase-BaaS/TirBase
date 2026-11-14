// SPDX-License-Identifier: AGPL-3.0-only

//! Group-commit batcher for security events and effects-ledger writes
//! (19.4, PV-15.4).
//!
//! Low/Medium severity events are buffered for a 50ms window before flush.
//! `High` and `Critical` severity events bypass the batcher and flush
//! immediately (including any buffered events) so security-critical records
//! are never delayed by flash-wear throttling.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use tirbase_core::events::{SecurityEvent, Severity};
use tirbase_core::traits::SecurityEventSink;

/// Default batching window (PV-15.4).
pub const DEFAULT_BATCH_WINDOW: Duration = Duration::from_millis(50);
/// Maximum throttle ceiling (PV-15.4).
pub const MAX_BATCH_WINDOW: Duration = Duration::from_millis(500);

/// Backend that performs the durable/fsync write of a batch.
/// Production can route to SQLite; tests observe flush calls.
pub trait EventBatchBackend: Send + Sync + std::fmt::Debug {
    fn flush(&self, batch: Vec<SecurityEvent>);
}

#[derive(Debug, Default)]
pub struct RecordingBatchBackend {
    pub flushes: Mutex<Vec<(u64, Vec<SecurityEvent>)>>,
}
impl RecordingBatchBackend {
    pub fn flush_count(&self) -> usize {
        self.flushes.lock().unwrap().len()
    }
    pub fn total_events(&self) -> usize {
        self.flushes
            .lock()
            .unwrap()
            .iter()
            .map(|(_, b)| b.len())
            .sum()
    }
    pub fn all_events(&self) -> Vec<SecurityEvent> {
        self.flushes
            .lock()
            .unwrap()
            .iter()
            .flat_map(|(_, b)| b.iter().cloned())
            .collect()
    }
}
impl EventBatchBackend for RecordingBatchBackend {
    fn flush(&self, batch: Vec<SecurityEvent>) {
        self.flushes
            .lock()
            .unwrap()
            .push((tirbase_core::traits::monotonic_now(), batch));
    }
}

#[derive(Debug)]
struct BatcherState {
    queue: VecDeque<SecurityEvent>,
    window: Duration,
    stop: bool,
    flush_count: u64,
}

#[derive(Debug)]
pub struct GroupCommitBatcher {
    state: Mutex<BatcherState>,
    cv: Condvar,
    backend: Arc<dyn EventBatchBackend>,
 /// In-memory mirror for gateway compatibility/readers.
    mirror: Mutex<Vec<SecurityEvent>>,
}

impl GroupCommitBatcher {
    pub fn new(backend: Arc<dyn EventBatchBackend>) -> Arc<Self> {
        Self::with_window(backend, DEFAULT_BATCH_WINDOW)
    }

    pub fn with_window(backend: Arc<dyn EventBatchBackend>, window: Duration) -> Arc<Self> {
        let this = Arc::new(Self {
            state: Mutex::new(BatcherState {
                queue: VecDeque::new(),
                window,
                stop: false,
                flush_count: 0,
            }),
            cv: Condvar::new(),
            backend,
            mirror: Mutex::new(Vec::new()),
        });
        let worker = Arc::clone(&this);
        thread::Builder::new()
            .name("aef-event-batcher".into())
            .spawn(move || worker.run())
            .expect("spawn event batcher");
        this
    }

    fn is_high_priority(event: &SecurityEvent) -> bool {
        matches!(event.severity, Severity::High | Severity::Critical)
    }

    fn take_queue(state: &mut BatcherState) -> Vec<SecurityEvent> {
        state.queue.drain(..).collect()
    }

    fn flush_now(&self, mut batch: Vec<SecurityEvent>) {
        if batch.is_empty() {
            return;
        }
        let mut state = self.state.lock().unwrap();
 // Prepend any concurrently queued events in this flush boundary.
        let mut queued = Self::take_queue(&mut state);
        queued.append(&mut batch);
        state.flush_count += 1;
        drop(state);
        if !queued.is_empty() {
            self.backend.flush(queued);
        }
    }

    fn run(self: Arc<Self>) {
        loop {
            let mut state = self.state.lock().unwrap();
            if state.stop && state.queue.is_empty() {
                return;
            }
            if state.queue.is_empty() {
                state = self.cv.wait(state).unwrap();
                continue;
            }
            let window = state.window;
            let (guard, wait) = self.cv.wait_timeout(state, window).unwrap();
            state = guard;
            if state.stop && state.queue.is_empty() {
                return;
            }
 // Flush on timeout or explicit wake when stop/high-priority drained path queued work.
            let should_flush = wait.timed_out() || !state.queue.is_empty();
            if should_flush {
                let batch = Self::take_queue(&mut state);
                drop(state);
                self.backend.flush(batch);
            }
        }
    }

    pub fn set_window(&self, window: Duration) {
        let window = window.min(MAX_BATCH_WINDOW);
        let mut state = self.state.lock().unwrap();
        state.window = window;
        self.cv.notify_all();
    }

    pub fn window(&self) -> Duration {
        self.state.lock().unwrap().window
    }

    pub fn flush_count(&self) -> u64 {
        self.state.lock().unwrap().flush_count
    }

    pub fn pending_len(&self) -> usize {
        self.state.lock().unwrap().queue.len()
    }

    pub fn events(&self) -> Vec<SecurityEvent> {
        self.mirror.lock().unwrap().clone()
    }

    pub fn len(&self) -> usize {
        self.mirror.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn stop(&self) {
        let mut state = self.state.lock().unwrap();
        state.stop = true;
        self.cv.notify_all();
        drop(state);
 // Give worker a moment to flush; tests may also call stop explicitly.
        let deadline = tirbase_core::traits::monotonic_now() + 250_000;
        while tirbase_core::traits::monotonic_now() < deadline {
            if self.pending_len() == 0 {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
 // Final synchronous flush for determinism.
        let mut state = self.state.lock().unwrap();
        let batch = Self::take_queue(&mut state);
        state.flush_count += 1;
        drop(state);
        if !batch.is_empty() {
            self.backend.flush(batch);
        }
    }
}

impl SecurityEventSink for GroupCommitBatcher {
    fn emit(&self, event: SecurityEvent) {
        {
            let mut m = self.mirror.lock().unwrap();
            if m.len() >= super::security_sink::MAX_EVENTS {
                m.remove(0);
            }
            m.push(event.clone());
        }
        if Self::is_high_priority(&event) {
 // 19.4: High/Critical bypass the batcher and are written immediately.
            self.flush_now(vec![event]);
            self.cv.notify_all();
            return;
        }
        let mut state = self.state.lock().unwrap();
        state.queue.push_back(event);
 // Non-urgent events wait for the 50ms window/worker flush.
        self.cv.notify_all();
    }
}
