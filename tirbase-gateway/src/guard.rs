//! Gateway Stage 16–19 executor wiring (CLAIM-15.1–15.7, PV-4.20, PV-4.21).
//!
//! `SqliteStage16Store` implements `tirbase_guard::Stage16Store` with one atomic
//! SQLite transaction; fsync occurs at commit under `synchronous=FULL`.
//! Task 15.6 production caller: this module provides per-target async execution
//! helpers; `CommandGuard::admit_stages_0_to_15_with_pipeline()` is synchronous.

use std::sync::Mutex;

use rusqlite::{Connection, TransactionBehavior};

use crate::db::anti_replay_windows::{
    self, AntiReplayCheck, DEFAULT_FORWARD_GAP_G, DEFAULT_WINDOW_W,
};
use crate::db::applied_effects_ledger::{self, AppliedEffectRow, EffectState};
use crate::db::idempotency_keys::{self, IdempotencyRow};

pub use tirbase_guard::{
    coarse_for_rejection, commit_dispatch_finalize, stage17_acceptance, stage17_rejection,
    CoarseRejection, EffectTerminalState, Stage16Error, Stage16Request, Stage16Store,
};

#[derive(Debug)]
pub struct SqliteStage16Store {
    conn: Mutex<Connection>,
}

impl SqliteStage16Store {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| format!("create {parent:?}: {e}"))?;
            }
        }
        // Use the migration framework on an existing primary.db path when present,
        // but preserve the legacy direct-open behavior for isolated test DBs.
        let conn = Connection::open(path).map_err(|e| format!("open stage16 db: {e}"))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| format!("journal_mode: {e}"))?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| format!("synchronous: {e}"))?;
        crate::db::sqlite_errors::apply_hardening_pragmas(&conn, crate::db::DbKind::Primary)
            .map_err(|e| e.to_string())?;
        crate::db::migrations::apply_migrations(
            &conn,
            crate::db::DbKind::Primary,
            crate::db::migrations::primary_migrations(),
        )
        .map_err(|e| e.to_string())?;
        // Keep legacy per-module create helpers for stores still evolving outside
        // migration v1 (decided_outcomes schema differs from design in current
        // Stage 16 implementation; migration creates the design table name).
        crate::db::decided_outcomes::SqliteDecidedOutcomesStore::open(path).ok();
        applied_effects_ledger::create_table(&conn)?;
        anti_replay_windows::create_table(&conn)?;
        idempotency_keys::create_table(&conn)?;
        crate::db::single_writer_leases::create_table(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    pub fn count_idempotency_keys(&self, issuer_did: &str, target_id: &str) -> Result<i64, String> {
        self.lock()
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {} WHERE issuer_did=?1 AND target_id=?2",
                    crate::db::idempotency_keys::IDEMPOTENCY_KEYS_TABLE
                ),
                rusqlite::params![issuer_did, target_id],
                |r| r.get(0),
            )
            .map_err(|e| format!("count idempotency: {e}"))
    }
    pub fn anti_replay_highest(
        &self,
        issuer_did: &str,
        target_id: &str,
        epoch: u64,
    ) -> Result<Option<u64>, String> {
        use rusqlite::OptionalExtension;
        self.lock().query_row(
            &format!("SELECT highest_seen FROM {} WHERE issuer_did=?1 AND target_id=?2 AND enrollment_epoch=?3", crate::db::anti_replay_windows::ANTI_REPLAY_WINDOWS_TABLE),
            rusqlite::params![issuer_did, target_id, epoch as i64],
            |r| r.get::<_, i64>(0).map(|v| v as u64),
        ).optional().map_err(|e| format!("load anti_replay: {e}"))
    }
    pub fn lease_holder(&self, target_id: &str) -> Result<Option<String>, String> {
        use rusqlite::OptionalExtension;
        self.lock()
            .query_row(
                &format!(
                    "SELECT issuer_did FROM {} WHERE target_id=?1",
                    crate::db::single_writer_leases::SINGLE_WRITER_LEASES_TABLE
                ),
                rusqlite::params![target_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| format!("load lease: {e}"))
    }
    pub fn effect_state(&self, entry_id: &[u8; 16]) -> Result<Option<String>, String> {
        use rusqlite::OptionalExtension;
        self.lock()
            .query_row(
                &format!(
                    "SELECT state FROM {} WHERE entry_id=?1",
                    crate::db::applied_effects_ledger::APPLIED_EFFECTS_LEDGER_TABLE
                ),
                rusqlite::params![entry_id.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| format!("load effect: {e}"))
    }
}

impl Stage16Store for SqliteStage16Store {
    fn commit_actuating(&self, req: &Stage16Request<'_>) -> Result<(), Stage16Error> {
        let cmd = req.cmd;
        let mut conn = self.lock();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| Stage16Error::Store(format!("begin immediate: {e}")))?;

        // (b) non-mutating idempotency check first (CLAIM-20.5/PV-5.6): a known
        // (issuer_did,target_id,idempotency_key) returns the stored outcome without
        // a second actuation, even on retry.
        if let Some(existing) = idempotency_keys::lookup_tx(
            &tx,
            cmd.issuer_did.as_str(),
            cmd.target_id.as_str(),
            &cmd.idempotency_key,
            req.now_est,
        )
        .map_err(Stage16Error::Store)?
        {
            return Err(Stage16Error::IdempotencyHit {
                original_result: existing.original_result,
            });
        }

        // (a) non-mutating anti-replay check (CLAIM-20.2/PV-5.5): rejected/duplicate
        // sequences must not mutate state; only committed commands advance the window.
        let row = anti_replay_windows::load_window_tx(
            &tx,
            cmd.issuer_did.as_str(),
            cmd.target_id.as_str(),
            cmd.enrollment_epoch,
        )
        .map_err(Stage16Error::Store)?;
        match anti_replay_windows::check_and_advance(
            row.as_ref(),
            cmd.sequence_number,
            DEFAULT_WINDOW_W,
            DEFAULT_FORWARD_GAP_G,
        ) {
            AntiReplayCheck::Replay | AntiReplayCheck::OutsideWindow => {
                return Err(Stage16Error::AntiReplay)
            }
            AntiReplayCheck::Accepted { .. } => {}
        }

        // (c) acquire SingleWriterLease inside the same transaction
        if let Err(e) = crate::db::single_writer_leases::acquire_tx(
            &tx,
            cmd.target_id.as_str(),
            cmd.issuer_did.as_str(),
            req.now_mono_secs,
            req.lease_duration_secs,
            req.max_consecutive_renewals,
        ) {
            return Err(match e {
                crate::db::single_writer_leases::LeaseAcquireError::HeldByOther { holder } => {
                    Stage16Error::LeaseHeld { holder }
                }
                crate::db::single_writer_leases::LeaseAcquireError::Cooldown { until_mono } => {
                    Stage16Error::LeaseHeld {
                        holder: format!("cooldown_until_{until_mono}"),
                    }
                }
                crate::db::single_writer_leases::LeaseAcquireError::Store(s) => {
                    Stage16Error::Store(s)
                }
            });
        }

        // (d) advance anti-replay
        let AntiReplayCheck::Accepted {
            new_highest,
            new_bitmap,
        } = anti_replay_windows::check_and_advance(
            row.as_ref(),
            cmd.sequence_number,
            DEFAULT_WINDOW_W,
            DEFAULT_FORWARD_GAP_G,
        )
        else {
            return Err(Stage16Error::AntiReplay);
        };
        anti_replay_windows::upsert_window_tx(
            &tx,
            cmd.issuer_did.as_str(),
            cmd.target_id.as_str(),
            cmd.enrollment_epoch,
            new_highest,
            new_bitmap,
            row.as_ref()
                .map(|r| r.forward_gap)
                .unwrap_or(DEFAULT_FORWARD_GAP_G),
        )
        .map_err(Stage16Error::Store)?;

        // (e) insert idempotency key
        let retention =
            tirbase_guard::commit::clamp_idempotency_retention_secs(req.idempotency_retention_secs);
        idempotency_keys::insert_tx(
            &tx,
            &IdempotencyRow {
                issuer_did: cmd.issuer_did.as_str().to_string(),
                target_id: cmd.target_id.as_str().to_string(),
                idempotency_key: cmd.idempotency_key,
                original_result: req.original_result_json.to_string(),
                recorded_at_est: req.now_est,
                expires_at_est: req.now_est.saturating_add(retention),
            },
        )
        .map_err(Stage16Error::Store)?;

        // (f) write Actuating record (first durable state)
        applied_effects_ledger::insert_actuating_tx(
            &tx,
            &AppliedEffectRow {
                entry_id: req.entry_id,
                issuer_did: cmd.issuer_did.as_str().to_string(),
                target_id: cmd.target_id.as_str().to_string(),
                param: cmd.param.clone(),
                desired_mantissa: cmd.desired_state.mantissa,
                desired_exponent: cmd.desired_state.exponent,
                desired_unit_id: cmd.desired_state.unit_id,
                sequence_number: cmd.sequence_number,
                idempotency_key: cmd.idempotency_key,
                expiry_est: cmd.expiry_est,
                policy_version: cmd.policy_version,
                enrollment_epoch: cmd.enrollment_epoch,
                state: EffectState::Actuating,
                actuating_ts: req.actuating_ts,
                completion_ts: None,
                driver_response: None,
            },
        )
        .map_err(Stage16Error::Store)?;

        tx.execute(
            &format!("INSERT OR REPLACE INTO {} (issuer_did,target_id,sequence_number,enrollment_epoch,accepted,rejection_category,detail) VALUES (?1,?2,?3,?4,1,NULL,?5)", crate::db::decided_outcomes::DECIDED_OUTCOMES_TABLE),
            rusqlite::params![cmd.issuer_did.as_str(), cmd.target_id.as_str(), cmd.sequence_number as i64, cmd.enrollment_epoch as i64, req.original_result_json],
        ).map_err(|e| Stage16Error::Store(format!("decided_outcomes: {e}")))?;

        // COMMIT => synchronous=FULL WAL fsync boundary before dispatch (INV-12).
        tx.commit()
            .map_err(|e| Stage16Error::Store(format!("commit/fsync: {e}")))
    }

    fn finalize_terminal(
        &self,
        entry_id: &[u8; 16],
        target_id: &str,
        issuer_did: &str,
        state: EffectTerminalState,
        completion_ts: i64,
        driver_response: Option<&[u8]>,
    ) -> Result<(), String> {
        let es = match state {
            EffectTerminalState::Complete => EffectState::Complete,
            EffectTerminalState::Failed => EffectState::Failed,
            EffectTerminalState::Unknown => EffectState::Unknown,
        };
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(|e| format!("begin: {e}"))?;
        applied_effects_ledger::update_terminal_state_tx(
            &tx,
            entry_id,
            es,
            completion_ts,
            driver_response,
        )?;
        crate::db::single_writer_leases::release_tx(&tx, target_id, issuer_did)?;
        tx.commit().map_err(|e| format!("commit: {e}"))
    }
}

/// Stage 15.6 executor split helper: evaluate Stages 0–15 (spawn_blocking-safe)
/// then run 16–19. DB reads in admit are allowed on a blocking pool.
pub async fn admit_and_dispatch_blocking<W, R>(
    guard: std::sync::Arc<tirbase_guard::CommandGuard>,
    cmd: tirbase_types::command::CommandMessage,
    ctx_source_key: String,
    token: Vec<u8>,
    ingress: tirbase_guard::IngressSource,
    now_est: i64,
    simulate: bool,
    store: std::sync::Arc<SqliteStage16Store>,
    mut proxy: tirbase_guard::DriverProxy<W>,
    frame: Vec<u8>,
    mut driver_reader: R,
    now_mono_secs: i64,
) -> serde_json::Value
where
    W: std::io::Write + Send + 'static,
    R: std::io::Read + Send + 'static,
{
    if simulate {
        let sim_ctx = tirbase_guard::admit::AdmitContext {
            ingress,
            source_key: &ctx_source_key,
            biscuit_token: Some(&token),
            now_est_secs: Some(now_est),
            simulate: true,
        };
        let d = guard.simulate(&cmd, &sim_ctx);
        return match d {
            tirbase_guard::AdmitDecision::Simulated {
                would_accept: true,
                derived_role,
                ..
            } => {
                serde_json::json!({"status":"simulated","would_accept":true,"derived_role":format!("{derived_role:?}")})
            }
            tirbase_guard::AdmitDecision::Simulated {
                would_accept: false,
                rejection,
                ..
            } => {
                let (cat, detail, retry) = rejection.unwrap_or((
                    tirbase_guard::AdmitRejection::Unsupported,
                    "rejected".into(),
                    None,
                ));
                let mut v = tirbase_guard::stage17_rejection(&cmd, cat, &detail, false);
                if let Some(r) = retry {
                    v["retry_after_secs"] = serde_json::json!(r);
                }
                v["simulated"] = serde_json::json!(true);
                v
            }
            other => serde_json::json!({"status":"simulated","decision":format!("{other:?}")}),
        };
    }
    let guard2 = guard.clone();
    let cmd2 = cmd.clone();
    let sk = ctx_source_key.clone();
    let tok = token.clone();
    let decision = match tokio::task::spawn_blocking(move || {
        let ctx = tirbase_guard::admit::AdmitContext {
            ingress,
            source_key: &sk,
            biscuit_token: Some(&tok),
            now_est_secs: Some(now_est),
            simulate: false,
        };
        guard2.admit_stages_0_to_15_with_pipeline(&cmd2, &ctx)
    })
    .await
    {
        Ok(d) => d,
        Err(e) => {
            return tirbase_guard::stage17_rejection(
                &cmd,
                tirbase_guard::AdmitRejection::Unsupported,
                &format!("admit join: {e}"),
                false,
            )
        }
    };
    match decision {
        tirbase_guard::AdmitDecision::Accepted {
            idempotency_cache_hit: true,
            ..
        } => serde_json::json!({"status":"accepted","idempotency_cache_hit":true}),
        tirbase_guard::AdmitDecision::Accepted { .. } => {
            let entry_id = make_entry_id(&cmd);
            let store2 = store.clone();
            let cmd3 = cmd.clone();
            tokio::task::spawn_blocking(move || {
                tirbase_guard::commit_dispatch_finalize(
                    &*store2,
                    &cmd3,
                    entry_id,
                    now_est,
                    now_est,
                    now_mono_secs,
                    &mut proxy,
                    &frame,
                    &mut driver_reader,
                    now_est,
                )
            })
            .await
            .unwrap_or_else(|e| {
                tirbase_guard::stage17_rejection(
                    &cmd,
                    tirbase_guard::AdmitRejection::Unsupported,
                    &format!("dispatch join: {e}"),
                    false,
                )
            })
        }
        tirbase_guard::AdmitDecision::Rejected {
            category,
            detail,
            retry_after_secs,
        } => {
            let mut v = tirbase_guard::stage17_rejection(&cmd, category, &detail, false);
            if let Some(r) = retry_after_secs {
                v["retry_after_secs"] = serde_json::json!(r);
            }
            v
        }
        other => serde_json::json!({"status":"unexpected","decision":format!("{other:?}")}),
    }
}

fn make_entry_id(cmd: &tirbase_types::command::CommandMessage) -> [u8; 16] {
    // Deterministic 16-byte entry id derived from command identity.
    // (Production deployments may use a monotonic allocator; this is stable for tests/wiring.)
    let mut id = [0u8; 16];
    id[0..8].copy_from_slice(&cmd.sequence_number.to_le_bytes());
    id[8..16].copy_from_slice(&cmd.enrollment_epoch.to_le_bytes());
    for (i, b) in cmd.idempotency_key.iter().enumerate() {
        id[i % 16] ^= *b;
    }
    for (i, b) in cmd.target_id.as_str().bytes().enumerate() {
        id[i % 16] ^= b;
    }
    id
}
