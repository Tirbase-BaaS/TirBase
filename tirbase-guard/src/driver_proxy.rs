//! `DriverProxy` — the *only* path from an [`ActuationPermit`] to a driver
//! (PV-4.4, CLAIM-11.3).
//!
//! The guard holds the device I/O endpoint (fd0 / socketpair end).  A driver in
//! `tirbase-drivers` is a pure codec: it never receives an [`ActuationPermit`]
//! and it never touches device I/O.  The proxy consumes the permit, derives an
//! [`ActuationPermitRef`] for codec use, and writes the encoded frame to the
//! guard-owned fd.
//!
//! All three command ingress paths (mesh, cloud API, local admin API) must
//! converge on [`CommandGuard::admit()`] in [`crate::guard`] and only then
//! reach this proxy.  The `trybuild` tests under
//! `tirbase-guard/tests/compile_fail/` enforce the bypass-proof property:
//! constructing an `ActuationPermit` or calling the proxy outside the guard's
//! `admit()` path is either impossible (sealed permit) or structurally gated.

use std::io::{self, Write};

use crate::permit::{ActuationPermit, ActuationPermitRef};

/// Guard-owned handle that dispatches an already-admitted actuation.
///
/// `DriverProxy` does **not** decide whether a command is allowed — that is
/// [`crate::guard::CommandGuard::admit()`]'s job.  It only forwards an
/// admitted, permit-bearing frame to the device fd.
#[derive(Debug)]
pub struct DriverProxy<W: Write + Send> {
    /// Guard-owned write end (fd0 / socketpair) to the device/driver boundary.
    device: W,
}

impl<W: Write + Send> DriverProxy<W> {
    pub fn new(device: W) -> Self {
        DriverProxy { device }
    }

    /// Consume `permit` and write `frame` to the device fd.
    ///
    /// The permit is consumed here so it cannot be reused (single-use).  The
    /// caller (guard pipeline Stage 18) is responsible for encoding the frame;
    /// drivers perform encode/decode only on plain types from `tirbase-types`.
    pub fn dispatch(
        &mut self,
        permit: ActuationPermit,
        frame: &[u8],
    ) -> io::Result<ActuationPermitRef> {
        let permit_ref = permit.into_ref();
        self.device.write_all(frame)?;
        self.device.flush()?;
        Ok(permit_ref)
    }

    /// Access the underlying device writer (crate-internal tests/diagnostics).
    pub(crate) fn device_mut(&mut self) -> &mut W {
        &mut self.device
    }
}

/// Ingress source — used by the guard to record that a command arrived over a
/// recognised path and to drive ingress-convergence tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressSource {
    Mesh,
    CloudApi,
    LocalAdmin,
}
