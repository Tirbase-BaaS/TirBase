// SPDX-License-Identifier: AGPL-3.0-only

//! Failpoint injection helpers for kill-at-every-step tests (PV-5.4, CLAIM-19.6).
//!
//! Production code uses [`ledger_fail_point!`] at durable write boundaries.
//! In normal builds this compiles to a no-op; when the `fail/failpoints`
//! feature is active (tests), a configured failpoint can force the operation
//! to return `Err(String)` so tests can verify no unhandled ledger state
//! remains.

pub use fail;

/// Evaluate a named failpoint at a ledger write boundary.
///
/// `expr` must evaluate to `Result<T, String>` in the error branch; the macro
/// returns early with that error when the failpoint is armed.
#[macro_export]
macro_rules! ledger_fail_point {
    ($name:expr) => {{
        $crate::failpoints::fail::fail_point!($name, |_| -> Result<(), String> {
            Err(format!("failpoint {}", $name))
        });
    }};
}

pub use ledger_fail_point;
