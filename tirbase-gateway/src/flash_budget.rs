// SPDX-License-Identifier: AGPL-3.0-only

//! Flash-write budget tracking and flash-wear throttling (PV-15.4, CLAIM-44.5/44.6).
//!
//! - Tracks durable writes at the **Linux block layer** for the block device backing
//! the gateway data directory (not SQLite logical counters).
//! - Default budget: 100 MB/day (configurable).
//! - When projected daily writes exceed budget, non-critical writes are throttled by
//! increasing the security-event group-commit window up to 500 ms.
//! - `HIGH` and `CRITICAL` SecurityEvents always bypass the budget limit and
//! flash-wear throttling and are written immediately.
//! - Exposes a 7-day rolling average of durable write bytes/day for the
//! `flash-wear-estimate` CLI.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tirbase_core::events::{emit, ReasonCode, SecurityEvent, SecurityEventCategory, Severity};

use crate::event_batcher::{DEFAULT_BATCH_WINDOW, MAX_BATCH_WINDOW};

pub const DEFAULT_FLASH_BUDGET_BYTES_PER_DAY: u64 = 100 * 1024 * 1024;
pub const FLASH_BUDGET_SAMPLE_INTERVAL: Duration = Duration::from_secs(60);
pub const FLASH_BUDGET_HISTORY: usize = 7 * 24 * 60; // 7 days of minute samples
const SECTOR_SIZE_BYTES: u64 = 512;

/// Snapshot of flash-wear accounting for reporting/CLI.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct FlashWearEstimate {
    pub block_device: Option<String>,
    pub block_layer_supported: bool,
    pub budget_bytes_per_day: u64,
    pub rolling_7d_avg_bytes_per_day: u64,
    pub projected_bytes_per_day: u64,
    pub today_bytes: u64,
    pub throttling_active: bool,
    pub group_commit_window_ms: u64,
    pub high_critical_bypass: bool,
}

#[derive(Debug)]
struct Sample {
    at_unix: i64,
    cumulative_write_bytes: Option<u64>,
}

#[derive(Debug)]
struct FlashBudgetState {
    samples: VecDeque<Sample>,
    today_start_unix: i64,
    today_start_bytes: Option<u64>,
    last_bytes: Option<u64>,
}

impl Default for FlashBudgetState {
    fn default() -> Self {
        Self {
            samples: VecDeque::with_capacity(FLASH_BUDGET_HISTORY),
            today_start_unix: 0,
            today_start_bytes: None,
            last_bytes: None,
        }
    }
}

/// Linux block-layer write counter for the device backing `data_path`.
#[derive(Debug, Clone)]
pub struct BlockLayerCounter {
    data_path: PathBuf,
    block_device: Option<String>,
    stat_path: Option<PathBuf>,
}

impl BlockLayerCounter {
    pub fn for_data_path(data_path: impl Into<PathBuf>) -> Self {
        let data_path = data_path.into();
        let block_device = resolve_block_device(&data_path);
        let stat_path = block_device
            .as_ref()
            .map(|dev| PathBuf::from(format!("/sys/block/{dev}/stat")));
        Self {
            data_path,
            block_device,
            stat_path,
        }
    }

    pub fn supported(&self) -> bool {
        self.stat_path
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    pub fn block_device(&self) -> Option<String> {
        self.block_device.clone()
    }

 /// Returns cumulative sectors written * 512 for the backing block device.
    pub fn read_cumulative_write_bytes(&self) -> io::Result<u64> {
        let stat_path = self
            .stat_path
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "block stat unavailable"))?;
        let body = fs::read_to_string(stat_path)?;
        parse_write_sectors(&body)
            .map(|sectors| sectors.saturating_mul(SECTOR_SIZE_BYTES))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("could not parse {}", stat_path.display()),
                )
            })
    }

    pub fn data_path(&self) -> &Path {
        &self.data_path
    }
}

fn parse_write_sectors(stat: &str) -> Option<u64> {
 // /sys/block/<dev>/stat fields:
 // 1 read_ios 2 read_merges 3 read_sectors 4 read_ticks
 // 5 write_ios 6 write_merges 7 write_sectors ...
    let fields: Vec<&str> = stat.split_whitespace().collect();
    fields.get(6).and_then(|v| v.parse::<u64>().ok())
}

fn resolve_block_device(path: &Path) -> Option<String> {
 // Best-effort Linux resolution: find mount source device for path, then map to /sys/block.
    let mount_dev = find_mount_source(path)?;
    let name = mount_dev
        .strip_prefix("/dev/")
        .unwrap_or(&mount_dev)
        .to_string();
 // Partition (e.g. nvme0n1p1, sda1, mmcblk0p2) -> base block device if present.
    if Path::new(&format!("/sys/block/{name}")).exists() {
        return Some(name);
    }
 // Try trimming partition suffix.
    let trimmed = trim_partition_suffix(&name);
    if Path::new(&format!("/sys/block/{trimmed}")).exists() {
        return Some(trimmed);
    }
    Some(name)
}

fn find_mount_source(path: &Path) -> Option<String> {
    let target = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mounts = fs::read_to_string("/proc/self/mountinfo")
        .or_else(|_| fs::read_to_string("/proc/mounts"))
        .ok()?;
    let mut best: Option<(usize, String)> = None;
    for line in mounts.lines() {
 // mountinfo: ... - fstype source superopts
        let source = if line.contains(" - ") {
            let parts: Vec<&str> = line.splitn(2, " - ").collect();
            let right: Vec<&str> = parts.get(1)?.split_whitespace().collect();
            right.get(1).map(|s| s.to_string())
        } else {
 // /proc/mounts: source target fstype ...
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts.first().map(|s| s.to_string())
        };
        let mount_point = if line.contains(" - ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts.get(4).map(|s| s.replace("\\040", " "))
        } else {
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts.get(1).map(|s| s.replace("\\040", " "))
        };
        let (Some(src), Some(mp)) = (source, mount_point) else {
            continue;
        };
        let mp_path = Path::new(&mp);
        if target.starts_with(mp_path) {
            let len = mp.len();
            if best.as_ref().map(|b| len > b.0).unwrap_or(true) {
                best = Some((len, src));
            }
        }
    }
    best.map(|(_, s)| s)
}

fn trim_partition_suffix(name: &str) -> String {
 // nvme/mmcblk style: ...p<number>
    if let Some(idx) = name.rfind('p') {
        let (base, suffix) = name.split_at(idx + 1);
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) && base.len() > 1 {
 // keep base without trailing 'p' if it looks like mmcblk0p1/nvme0n1p1
            if name.contains("mmcblk") || name.contains("nvme") || name.contains("loop") {
                return name[..idx].to_string();
            }
        }
    }
 // sdX/vdX style: trailing digits
    let trimmed = name.trim_end_matches(|c: char| c.is_ascii_digit());
    if trimmed.len() < name.len() && (name.starts_with("sd") || name.starts_with("vd") || name.starts_with("xvd") || name.starts_with("hd")) {
        return trimmed.to_string();
    }
    name.to_string()
}

fn now_unix_secs() -> i64 {
    tirbase_core::traits::wall_hint_secs().unwrap_or(0)
}

fn day_start(unix: i64) -> i64 {
    unix - unix.rem_euclid(86_400)
}

/// Production flash-wear budget/throttle controller (CLAIM-44.5, CLAIM-44.6).
pub struct FlashBudgetController {
    budget_bytes_per_day: AtomicU64,
    counter: BlockLayerCounter,
    state: Mutex<FlashBudgetState>,
    group_commit_window_ms: AtomicU64,
    throttling_active: AtomicBool,
    security_log: RwLock<Option<Arc<crate::security_log::SecurityEventLog>>>,
}

impl std::fmt::Debug for FlashBudgetController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlashBudgetController")
            .field("budget_bytes_per_day", &self.budget_bytes_per_day.load(Ordering::Relaxed))
            .field("block_device", &self.counter.block_device())
            .field("supported", &self.counter.supported())
            .finish()
    }
}

impl FlashBudgetController {
    pub fn new(data_path: impl Into<PathBuf>, budget_bytes_per_day: u64) -> Arc<Self> {
        Arc::new(Self {
            budget_bytes_per_day: AtomicU64::new(budget_bytes_per_day.max(1)),
            counter: BlockLayerCounter::for_data_path(data_path),
            state: Mutex::new(FlashBudgetState::default()),
            group_commit_window_ms: AtomicU64::new(DEFAULT_BATCH_WINDOW.as_millis() as u64),
            throttling_active: AtomicBool::new(false),
            security_log: RwLock::new(None),
        })
    }

 /// Attach the security log whose batcher window is throttled for non-critical writes.
    pub fn attach_security_log(&self, log: Arc<crate::security_log::SecurityEventLog>) {
        *self.security_log.write().unwrap_or_else(|p| p.into_inner()) = Some(log);
    }

    pub fn budget_bytes_per_day(&self) -> u64 {
        self.budget_bytes_per_day.load(Ordering::Relaxed)
    }

    pub fn set_budget_bytes_per_day(&self, budget: u64) {
        self.budget_bytes_per_day.store(budget.max(1), Ordering::Relaxed);
    }

    pub fn group_commit_window(&self) -> Duration {
        Duration::from_millis(self.group_commit_window_ms.load(Ordering::Relaxed))
    }

    pub fn throttling_active(&self) -> bool {
        self.throttling_active.load(Ordering::Relaxed)
    }

    fn sample_once(&self) {
        let now = now_unix_secs();
        let cumulative = self.counter.read_cumulative_write_bytes().ok();
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());

 // Handle counter reset (reboot/wrap) by rebasing.
        if let (Some(prev), Some(cur)) = (st.last_bytes, cumulative) {
            if cur < prev {
                st.today_start_bytes = Some(cur);
                st.samples.clear();
            }
        }
        st.last_bytes = cumulative;

        let ds = day_start(now);
        if st.today_start_unix != ds {
            st.today_start_unix = ds;
            st.today_start_bytes = cumulative;
        }
        if st.today_start_bytes.is_none() {
            st.today_start_bytes = cumulative;
        }

        st.samples.push_back(Sample {
            at_unix: now,
            cumulative_write_bytes: cumulative,
        });
        while st.samples.len() > FLASH_BUDGET_HISTORY {
            st.samples.pop_front();
        }
        drop(st);
    }

 /// Compute estimate/projection and apply throttling policy (PV-15.4).
    pub fn evaluate(&self) -> FlashWearEstimate {
        self.sample_once();
        let now = now_unix_secs();
        let budget = self.budget_bytes_per_day();
        let (rolling_7d_avg, projected, today_bytes) = {
            let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            (self.rolling_7d_avg_locked(&st), self.projected_locked(&st, now), self.today_bytes_locked(&st))
        };

        let (new_window, active) = throttle_window_for_projection(projected, budget);
        self.group_commit_window_ms
            .store(new_window.as_millis() as u64, Ordering::Relaxed);
        let was_active = self.throttling_active.swap(active, Ordering::Relaxed);
        if active && !was_active {
            emit(
                SecurityEvent::new(
                    SecurityEventCategory::Diagnostic,
                    Severity::Medium,
                    ReasonCode::FlashBudgetThrottlingActivated,
                )
                .with_detail(format!(
                    "flash-wear throttle activated: projected={projected} budget={budget} window_ms={}",
                    new_window.as_millis()
                )),
            );
        } else if !active && was_active {
            emit(
                SecurityEvent::new(
                    SecurityEventCategory::Diagnostic,
                    Severity::Low,
                    ReasonCode::FlashBudgetThrottlingDeactivated,
                )
                .with_detail("flash-wear throttle deactivated; within budget".to_string()),
            );
        }

 // Apply to non-critical batching path only. HIGH/CRITICAL events bypass the
 // batcher/window in SecurityEventLog/GroupCommitBatcher and are persisted
 // immediately regardless of this window.
        if let Some(log) = self.security_log.read().unwrap_or_else(|p| p.into_inner()).clone() {
            if let Some(batcher) = log.batcher() {
                batcher.set_window(new_window);
            }
        }

        FlashWearEstimate {
            block_device: self.counter.block_device(),
            block_layer_supported: self.counter.supported(),
            budget_bytes_per_day: budget,
            rolling_7d_avg_bytes_per_day: rolling_7d_avg,
            projected_bytes_per_day: projected,
            today_bytes,
            throttling_active: active,
            group_commit_window_ms: new_window.as_millis() as u64,
            high_critical_bypass: true,
        }
    }

    fn today_bytes_locked(&self, st: &FlashBudgetState) -> u64 {
        match (st.today_start_bytes, st.last_bytes) {
            (Some(start), Some(last)) => last.saturating_sub(start),
            _ => 0,
        }
    }

    fn projected_locked(&self, st: &FlashBudgetState, now: i64) -> u64 {
        let today = self.today_bytes_locked(st);
        let elapsed = (now - st.today_start_unix).max(1) as u64;
        let elapsed = elapsed.min(86_400);
 // project full-day bytes from today's observed block-layer writes
        today.saturating_mul(86_400) / elapsed.max(1)
    }

    fn rolling_7d_avg_locked(&self, st: &FlashBudgetState) -> u64 {
        let Some((first, last)) = st.samples.front().zip(st.samples.back()) else {
            return 0;
        };
        let (Some(a), Some(b)) = (first.cumulative_write_bytes, last.cumulative_write_bytes) else {
            return 0;
        };
        let delta = b.saturating_sub(a);
        let secs = (last.at_unix - first.at_unix).max(1) as u64;
 // bytes/day over observed window
        delta.saturating_mul(86_400) / secs.max(1)
    }

    pub fn estimate(&self) -> FlashWearEstimate {
        self.evaluate()
    }

 /// Background tracker/throttle loop (production caller, CLAIM-44.5/44.6).
    pub fn spawn(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(FLASH_BUDGET_SAMPLE_INTERVAL);
            loop {
                tick.tick().await;
                let _ = this.evaluate();
            }
        })
    }

 /// Attach the global process controller (used by CLI/tests).
    pub fn install_global(self: &Arc<Self>) -> Arc<Self> {
        let _ = GLOBAL_FLASH_BUDGET.set(Arc::clone(self));
        global()
            .unwrap_or_else(|| Arc::clone(self))
    }
}

/// Compute throttled group-commit window from projected daily writes.
/// `HIGH`/`CRITICAL` events bypass this window (handled by event path).
pub fn throttle_window_for_projection(projected_bytes_per_day: u64, budget_bytes_per_day: u64) -> (Duration, bool) {
    if budget_bytes_per_day == 0 || projected_bytes_per_day <= budget_bytes_per_day {
        return (DEFAULT_BATCH_WINDOW, false);
    }
    let over = projected_bytes_per_day.saturating_sub(budget_bytes_per_day);
    let budget = budget_bytes_per_day.max(1);
 // Linear ramp: at 2x budget reach max window.
    let ratio = (over as f64 / budget as f64).min(1.0);
    let base = DEFAULT_BATCH_WINDOW.as_millis() as f64;
    let max = MAX_BATCH_WINDOW.as_millis() as f64;
    let ms = (base + (max - base) * ratio).round() as u64;
    let ms = ms.clamp(DEFAULT_BATCH_WINDOW.as_millis() as u64, MAX_BATCH_WINDOW.as_millis() as u64);
    (Duration::from_millis(ms), true)
}

static GLOBAL_FLASH_BUDGET: std::sync::OnceLock<Arc<FlashBudgetController>> = std::sync::OnceLock::new();

pub fn global() -> Option<Arc<FlashBudgetController>> {
    GLOBAL_FLASH_BUDGET.get().cloned()
}

/// Persist/load rolling sample state for CLI/report continuity.
pub fn state_path(primary_db_path: &Path) -> PathBuf {
    primary_db_path.with_file_name("flash_wear_state.json")
}

pub fn save_estimate(path: &Path, est: &FlashWearEstimate) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_vec_pretty(est).map_err(io::Error::other)?;
    fs::write(path, body)
}

pub fn load_estimate(path: &Path) -> io::Result<FlashWearEstimate> {
    let body = fs::read(path)?;
    serde_json::from_slice(&body).map_err(io::Error::other)
}

/// One-shot estimate for CLI: samples current block-layer counters and computes
/// projection using persisted state when available.
pub fn estimate_for_data_path(data_path: &Path, budget_bytes_per_day: u64) -> FlashWearEstimate {
    let ctl = FlashBudgetController::new(data_path, budget_bytes_per_day);
    let sp = state_path(data_path);
    if let Ok(prev) = load_estimate(&sp) {
 // Seed with prior view is not enough for rolling history without persisted samples;
 // return fresh estimate but preserve context in fields.
        let mut est = ctl.estimate();
        if !ctl.counter.supported() {
            est.rolling_7d_avg_bytes_per_day = prev.rolling_7d_avg_bytes_per_day.max(est.rolling_7d_avg_bytes_per_day);
        }
        let _ = save_estimate(&sp, &est);
        return est;
    }
    let est = ctl.estimate();
    let _ = save_estimate(&sp, &est);
    est
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_write_sectors_from_sys_block_stat() {
 // field 7 (0-indexed 6) is sectors written
        let stat = "  100 0 200 0  50 0 4096 0 0 0 0 0 0 0 0 0 0 0 0\n";
        assert_eq!(parse_write_sectors(stat), Some(4096));
        assert_eq!(4096 * SECTOR_SIZE_BYTES, 2 * 1024 * 1024);
    }

    #[test]
    fn throttle_ramps_to_500ms_and_deactivates_under_budget() {
        let (w, active) = throttle_window_for_projection(50 * 1024 * 1024, 100 * 1024 * 1024);
        assert_eq!(w, DEFAULT_BATCH_WINDOW);
        assert!(!active);
        let (w, active) = throttle_window_for_projection(150 * 1024 * 1024, 100 * 1024 * 1024);
        assert!(active);
        assert!(w >= DEFAULT_BATCH_WINDOW && w <= MAX_BATCH_WINDOW);
        let (w, active) = throttle_window_for_projection(300 * 1024 * 1024, 100 * 1024 * 1024);
        assert!(active);
        assert_eq!(w, MAX_BATCH_WINDOW);
    }

    #[test]
    fn trim_partition_suffix_handles_common_devices() {
        assert_eq!(trim_partition_suffix("sda1"), "sda");
        assert_eq!(trim_partition_suffix("nvme0n1p2"), "nvme0n1");
        assert_eq!(trim_partition_suffix("mmcblk0p1"), "mmcblk0");
        assert_eq!(trim_partition_suffix("vda"), "vda");
    }
}
