//! `DriverProxy` — the *only* path from an [`ActuationPermit`] to a driver
//! (PV-4.4, CLAIM-11.3).
//!
//! The guard holds the device I/O endpoint (fd0 / socketpair end). A driver in
//! `tirbase-drivers` is a pure codec: it never receives an [`ActuationPermit`]
//! and it never touches device I/O. The proxy consumes the permit, derives an
//! [`ActuationPermitRef`] for codec use, and writes the encoded frame to the
//! guard-owned fd.
//!
//! All three command ingress paths (mesh, cloud API, local admin API) must
//! converge on [`CommandGuard::admit()`] in [`crate::guard`] and only then
//! reach this proxy. The `trybuild` tests under
//! `tirbase-guard/tests/compile_fail/` enforce the bypass-proof property:
//! constructing an `ActuationPermit` or calling the proxy outside the guard's
//! `admit()` path is either impossible (sealed permit) or structurally gated.
//!
//! ## Out-of-process driver child (CLAIM-33.5/33.6/33.7)
//!
//! [`DriverProxy::spawn_child`] is the production spawn path. It creates the
//! `socketpair(AF_UNIX, SOCK_SEQPACKET)`, starts a **real** child process that
//! inherits the child end, verifies the peer credentials on the guard end,
//! hands the guard-owned device fd over via `SCM_RIGHTS`, and returns a
//! [`SupervisedDriver`] that owns both the proxy (parent end) and the child.
//! The child applies its seccomp-BPF/landlock sandbox (see
//! `tirbase_drivers::isolation::apply_child_sandbox`) before parsing frames.
//! Crash/restart accounting is driven through [`DriverLifecycle`] on the same
//! supervision path, so restart decisions and LOCKDOWN escalation reach the
//! guard's supervisor instead of staying test-only.

#![allow(unsafe_code)]

use std::io::{self, Write};

use crate::permit::{ActuationPermit, ActuationPermitRef};

#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use tirbase_drivers::{
    apply_restart_decision, create_driver_socketpair, send_fd_via_scm_rights, verify_peercred,
    DriverCrashSupervisor, DriverLifecycle, DriverRestartDecision, IsolationError,
};

/// Guard-owned handle that dispatches an already-admitted actuation.
///
/// `DriverProxy` does **not** decide whether a command is allowed — that is
/// [`crate::guard::CommandGuard::admit()`]'s job. It only forwards an
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
 /// The permit is consumed here so it cannot be reused (single-use). The
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
    #[allow(dead_code)]
    pub(crate) fn device_mut(&mut self) -> &mut W {
        &mut self.device
    }
}

// ── Out-of-process driver child (CLAIM-33.5, CLAIM-33.6, CLAIM-33.7) ────────

/// Launch description for the persistent driver child process.
#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct ChildDriverConfig {
 /// Driver child executable (the sandboxed codec process).
    pub program: PathBuf,
 /// Extra child arguments; the socket fd argument is appended by the proxy.
    pub args: Vec<String>,
 /// Guard-owned device fd handed to the child via `SCM_RIGHTS` after the
 /// peer credentials have been verified. `None` starts a child with no
 /// device handoff (no `SCM_RIGHTS` message is sent).
    pub device_fd: Option<RawFd>,
 /// Signed config decision permitting a degraded (no landlock) sandbox.
    pub degraded_isolation_opt_in: bool,
 /// Expected peer uid; `None` means the guard's effective uid.
    pub expected_peer_uid: Option<u32>,
 /// Pipe the child's stdout/stderr instead of inheriting them (tests and
 /// diagnostics only; production inherits so child logs reach the journal).
    pub capture_output: bool,
}

/// Errors from spawning or supervising the driver child.
#[cfg(unix)]
#[derive(Debug)]
pub enum DriverSupervisionError {
 /// socketpair / SCM_RIGHTS / peercred failure from `tirbase-drivers`.
    Isolation(IsolationError),
 /// The child process could not be started.
    Spawn(io::Error),
}

#[cfg(unix)]
impl core::fmt::Display for DriverSupervisionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DriverSupervisionError::Isolation(e) => write!(f, "driver child isolation: {e}"),
            DriverSupervisionError::Spawn(e) => write!(f, "driver child spawn: {e}"),
        }
    }
}

#[cfg(unix)]
impl std::error::Error for DriverSupervisionError {}

#[cfg(unix)]
impl From<IsolationError> for DriverSupervisionError {
    fn from(e: IsolationError) -> Self {
        DriverSupervisionError::Isolation(e)
    }
}

/// Guard-side end of the driver socketpair, owned by the proxy.
#[cfg(unix)]
#[derive(Debug)]
pub struct DriverChildSocket {
    file: std::fs::File,
}

#[cfg(unix)]
impl DriverChildSocket {
    pub fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

#[cfg(unix)]
impl Write for DriverChildSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(unix)]
impl Read for DriverChildSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

#[cfg(unix)]
impl DriverProxy<DriverChildSocket> {
 /// Spawns the persistent driver child and returns its supervisor.
 ///
 /// Steps (CLAIM-33.5/33.6/33.7), in order:
 /// 1. `socketpair(AF_UNIX, SOCK_SEQPACKET)` — the guard keeps `parent_fd`.
 /// 2. Spawn the child with the inherited `child_fd` fd number; the child
 /// closes the guard end before `execve`.
 /// 3. Verify `SO_PEERCRED` on the guard end (Linux) before any write; a
 /// mismatch aborts the spawn and kills the child.
 /// 4. Pass the guard-owned device fd via `SCM_RIGHTS` when configured.
 ///
 /// The child applies its own seccomp/landlock sandbox before parsing the
 /// first frame (CLAIM-33.6).
    pub fn spawn_child(
        config: &ChildDriverConfig,
        lifecycle: DriverLifecycle,
    ) -> Result<SupervisedDriver, DriverSupervisionError> {
        let (proxy, child, peer) = spawn_child_parts(config)?;
        Ok(SupervisedDriver {
            config: config.clone(),
            proxy,
            child,
            lifecycle,
            peer,
        })
    }
}

/// Parent proxy, child handle, and optional `(uid, pid)` attributed by SCM_CREDENTIALS.
#[cfg(unix)]
type ChildParts = (DriverProxy<DriverChildSocket>, Child, Option<(u32, i32)>);

/// Builds the socketpair, child, peer credential check and fd handoff.
#[cfg(unix)]
fn spawn_child_parts(
    config: &ChildDriverConfig,
) -> Result<ChildParts, DriverSupervisionError> {
    let pair = create_driver_socketpair()?;
 // SAFETY: both fds were just returned by socketpair and are owned here.
    let parent_end = unsafe { OwnedFd::from_raw_fd(pair.parent_fd) };
 // SAFETY: as above.
    let child_end = unsafe { OwnedFd::from_raw_fd(pair.child_fd) };
    let parent_fd = parent_end.as_raw_fd();
    let child_fd = child_end.as_raw_fd();

    let mut command = Command::new(&config.program);
    command
 // Child mode/args come first so the fd flag is never mistaken for the
 // child's mode selector.
        .args(&config.args)
        .arg(tirbase_drivers::DRIVER_SOCKET_FD_ARG)
        .arg(child_fd.to_string())
        .stdin(Stdio::null());
    if config.device_fd.is_some() {
        command.arg("--expect-device-fd");
    }
    if config.degraded_isolation_opt_in {
        command.arg("--degraded-isolation-opt-in");
    }
    if config.capture_output {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::inherit());
    }
    {
        use std::os::unix::process::CommandExt;
        let guard_end_fd = parent_end.as_raw_fd();
 // SAFETY: `close` is async-signal-safe and the child has no other
 // threads or shared locks here. The child must not keep the guard end.
        unsafe {
            command.pre_exec(move || {
                if libc::close(guard_end_fd) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => return Err(DriverSupervisionError::Spawn(e)),
    };
 // The guard must not keep the child end open, or the child never sees EOF.
    drop(child_end);

    let expected_uid = config
        .expected_peer_uid
        .unwrap_or_else(|| unsafe { libc::geteuid() });
    let peer = match verify_peercred(parent_fd, Some(expected_uid)) {
        Ok(cred) if cred.1 > 0 => Some(cred),
        Ok(cred) => {
            terminate_child(&mut child);
            return Err(DriverSupervisionError::Isolation(
                IsolationError::PeerCredential(format!("invalid peer pid {}", cred.1)),
            ));
        }
 // Non-Linux targets have no SO_PEERCRED; the platform limitation is
 // reported by verify_peercred and recorded here as an absent check.
        Err(IsolationError::SandboxUnavailable { .. }) if !cfg!(target_os = "linux") => None,
        Err(e) => {
            terminate_child(&mut child);
            return Err(DriverSupervisionError::Isolation(e));
        }
    };

 // Peer identity verified: only now may the guard write to the socket, and
 // the first write is the device fd handed over via SCM_RIGHTS.
    if let Some(device_fd) = config.device_fd {
        if let Err(e) = send_fd_via_scm_rights(parent_fd, device_fd) {
            terminate_child(&mut child);
            return Err(DriverSupervisionError::Isolation(e));
        }
    }

    Ok((
        DriverProxy {
            device: DriverChildSocket {
 // The guard end is owned by the proxy from here on.
                file: parent_end.into(),
            },
        },
        child,
        peer,
    ))
}

#[cfg(unix)]
fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Owns the persistent driver child, its proxy, and crash/restart accounting.
#[cfg(unix)]
#[derive(Debug)]
pub struct SupervisedDriver {
    config: ChildDriverConfig,
    proxy: DriverProxy<DriverChildSocket>,
    child: Child,
    lifecycle: DriverLifecycle,
    peer: Option<(u32, i32)>,
}

#[cfg(unix)]
impl SupervisedDriver {
 /// Spawns the driver child with the default restart policy (1s initial,
 /// 60s max, 5 retries).
    pub fn start(config: ChildDriverConfig) -> Result<Self, DriverSupervisionError> {
        DriverProxy::spawn_child(&config, DriverLifecycle::default())
    }

 /// Spawns the driver child with an explicit restart policy (tests and
 /// deployments that need a tighter backoff window).
    pub fn start_with_lifecycle(
        config: ChildDriverConfig,
        lifecycle: DriverLifecycle,
    ) -> Result<Self, DriverSupervisionError> {
        DriverProxy::spawn_child(&config, lifecycle)
    }

    pub fn child_pid(&self) -> u32 {
        self.child.id()
    }

 /// `SO_PEERCRED` (uid, pid) captured before the first write. `None` on
 /// platforms without `SO_PEERCRED` (non-Linux).
    pub fn peer_credentials(&self) -> Option<(u32, i32)> {
        self.peer
    }

 /// Consume `permit` and write `frame` to the driver child socket.
    pub fn dispatch(
        &mut self,
        permit: ActuationPermit,
        frame: &[u8],
    ) -> io::Result<ActuationPermitRef> {
        if self.child.try_wait()?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "driver child exited before dispatch",
            ));
        }
        self.proxy.dispatch(permit, frame)
    }

 /// The guard-owned proxy for this child, so admitted frames reach it
 /// through the normal `CommandGuard::admit()` path.
    pub fn proxy_mut(&mut self) -> &mut DriverProxy<DriverChildSocket> {
        &mut self.proxy
    }

 /// Read a driver response frame (read-back from the codec child), bounded
 /// by `timeout` so a wedged child cannot block the guard pipeline.
    pub fn receive_with_timeout(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        let fd = self.proxy.device.raw_fd();
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
 // SAFETY: `pfd` is a valid pollfd for one descriptor.
        let rc = unsafe { libc::poll(&mut pfd, 1, millis) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if rc == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "driver child read timed out",
            ));
        }
        self.proxy.device.read(buf)
    }

 /// Non-blocking child exit probe used by the supervision loop.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

 /// Take the child's piped stdout (only when `capture_output` was set).
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

 /// Resets crash accounting after a stable child period.
    pub fn note_stable(&mut self) {
        self.lifecycle.record_stable();
    }

    pub fn consecutive_crashes(&self) -> u32 {
        self.lifecycle.consecutive_crashes()
    }

 /// Records a child crash, reports the decision to `supervisor`, and respawns
 /// the child after the computed backoff when the decision is `Restart`.
 ///
 /// On `EscalateLockdown` the child is left terminated so the caller can
 /// apply LOCKDOWN; the decision is also reported to the supervisor.
    pub fn restart_after_crash<S: DriverCrashSupervisor + ?Sized>(
        &mut self,
        supervisor: &S,
    ) -> Result<DriverRestartDecision, DriverSupervisionError> {
        let decision = self.lifecycle.record_crash();
        apply_restart_decision(decision, supervisor);
        if let DriverRestartDecision::Restart { backoff, .. } = decision {
            terminate_child(&mut self.child);
            std::thread::sleep(backoff);
            let (proxy, child, peer) = spawn_child_parts(&self.config)?;
            self.proxy = proxy;
            self.child = child;
            self.peer = peer;
        }
        Ok(decision)
    }

 /// Terminates the child (shutdown / after LOCKDOWN escalation).
    pub fn terminate(&mut self) {
        terminate_child(&mut self.child);
    }
}

#[cfg(unix)]
impl Drop for SupervisedDriver {
    fn drop(&mut self) {
        self.terminate();
    }
}

/// Poll interval for the gateway's driver supervision loop.
#[cfg(unix)]
pub const DRIVER_RESTART_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Ingress source — used by the guard to record that a command arrived over a
/// recognised path and to drive ingress-convergence tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressSource {
    Mesh,
    CloudApi,
    LocalAdmin,
}
