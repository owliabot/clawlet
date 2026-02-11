//! `clawlet stop` — stop a running clawlet daemon.
//!
//! Reads the PID file, sends SIGTERM, waits up to 5 seconds, then SIGKILL
//! if needed. Shared helper [`stop_running_instance`] is reused by `start`.

use std::fmt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Custom error type (Issue #3)
// ---------------------------------------------------------------------------

/// Structured error type for stop operations, replacing brittle string matching.
#[derive(Debug)]
#[allow(dead_code)]
pub enum StopError {
    /// Cannot determine whether the PID belongs to clawlet.
    CannotVerify { pid: i32, detail: String },
    /// Permission denied when trying to signal the process.
    PermissionDenied { pid: i32 },
    /// The process disappeared unexpectedly or PID file was invalid.
    ProcessNotFound { detail: String },
    /// The process survived SIGKILL.
    StaleProcess { pid: i32 },
    /// Platform not supported.
    Unsupported,
    /// Generic / IO errors.
    Other(String),
}

impl fmt::Display for StopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StopError::CannotVerify { pid, detail } => write!(
                f,
                "cannot verify that PID {pid} is a clawlet process ({detail}); \
                 use --force to stop it anyway, or kill it manually"
            ),
            StopError::PermissionDenied { pid } => {
                write!(f, "permission denied when signaling PID {pid}")
            }
            StopError::ProcessNotFound { detail } => write!(f, "{detail}"),
            StopError::StaleProcess { pid } => {
                write!(
                    f,
                    "PID {pid} is still alive after SIGKILL; not removing PID file"
                )
            }
            StopError::Unsupported => write!(f, "stop is only supported on Unix targets"),
            StopError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for StopError {}

/// Resolve the data directory (default: ~/.clawlet).
pub fn resolve_data_dir(data_dir: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(dir) = data_dir {
        return Ok(dir);
    }
    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    Ok(home.join(".clawlet"))
}

/// Check whether a process is alive via `kill(pid, 0)`.
#[cfg(unix)]
fn process_alive(pid: i32) -> bool {
    let ret = unsafe { libc::kill(pid, 0) };
    if ret == 0 {
        return true;
    }
    // EPERM means process exists but we lack permission — still alive.
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn process_alive(_pid: i32) -> bool {
    false
}

enum VerifyResult {
    IsClawlet,
    NotClawlet,
    CannotVerify,
}

/// Extract the basename (filename without directories) from a path string.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Verify that the given PID belongs to a clawlet process.
///
/// Uses strict basename matching: extracts argv\[0\] from `/proc/{pid}/cmdline`
/// (splitting on null bytes) or `ps -o comm=`, and checks that the executable
/// basename equals exactly "clawlet".
fn verify_is_clawlet(pid: i32) -> VerifyResult {
    // Try procfs first (Linux).
    let cmdline_path = format!("/proc/{pid}/cmdline");
    if let Ok(bytes) = std::fs::read(&cmdline_path) {
        if bytes.is_empty() {
            return VerifyResult::CannotVerify;
        }
        // cmdline is null-separated; argv[0] is the first element.
        let argv0_bytes = bytes.split(|&b| b == 0).next().unwrap_or(&bytes);
        let argv0 = String::from_utf8_lossy(argv0_bytes);
        let exe_name = basename(&argv0);
        return if exe_name == "clawlet" {
            VerifyResult::IsClawlet
        } else {
            VerifyResult::NotClawlet
        };
    }

    // Fall back to `ps` (works on macOS and Linux).
    match std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
    {
        Ok(output) if output.status.success() => {
            let comm = String::from_utf8_lossy(&output.stdout);
            let exe_name = basename(comm.trim());
            if exe_name == "clawlet" {
                VerifyResult::IsClawlet
            } else {
                VerifyResult::NotClawlet
            }
        }
        _ => VerifyResult::CannotVerify,
    }
}

// ---------------------------------------------------------------------------
// pidfd-based race-free signaling (Linux ≥ 5.1)
// ---------------------------------------------------------------------------

/// Attempt to open a pidfd and send a signal race-free.
/// Returns `Some(Ok(()))` if successfully sent, `Some(Err(_))` on pidfd error,
/// or `None` if pidfd syscalls are unavailable.
#[cfg(target_os = "linux")]
fn pidfd_send(pid: i32, sig: i32) -> Option<Result<(), std::io::Error>> {
    // pidfd_open = 434 on x86_64, 434 on aarch64
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0i32) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ENOSYS) => None, // kernel too old
            _ => Some(Err(err)),
        };
    }
    let ret = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, fd as i32, sig, 0usize, 0u32) };
    unsafe { libc::close(fd as i32) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ENOSYS) => None, // shouldn't happen but be safe
            _ => Some(Err(err)),
        };
    }
    Some(Ok(()))
}

#[cfg(not(target_os = "linux"))]
fn pidfd_send(_pid: i32, _sig: i32) -> Option<Result<(), std::io::Error>> {
    None
}

/// Send a signal to `pid`, using pidfd when available for race-free delivery.
/// Falls back to re-verifying identity + `kill()` on other platforms.
///
/// Returns `Ok(true)` if signal sent, `Ok(false)` if process already gone (ESRCH).
#[cfg(unix)]
fn safe_signal(pid: i32, sig: i32) -> Result<bool, StopError> {
    // Try pidfd path first (race-free).
    if let Some(result) = pidfd_send(pid, sig) {
        return match result {
            Ok(()) => Ok(true),
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(false),
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                Err(StopError::PermissionDenied { pid })
            }
            Err(e) => Err(StopError::Other(format!(
                "pidfd_send_signal to PID {pid}: {e}"
            ))),
        };
    }

    // Fallback: re-verify identity right before kill() to shrink the TOCTOU window.
    match verify_is_clawlet(pid) {
        VerifyResult::IsClawlet => { /* proceed */ }
        VerifyResult::NotClawlet => {
            return Err(StopError::Other(format!(
                "PID {pid} is no longer a clawlet process (recycled?)"
            )));
        }
        VerifyResult::CannotVerify => {
            // Best-effort: if we already verified once, continue.
        }
    }

    let ret = unsafe { libc::kill(pid, sig) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ESRCH) => Ok(false),
            Some(libc::EPERM) => Err(StopError::PermissionDenied { pid }),
            _ => Err(StopError::Other(format!(
                "failed to send signal {sig} to PID {pid}: {err}"
            ))),
        };
    }
    Ok(true)
}

/// Stop a running clawlet instance identified by the PID file in `data_dir`.
///
/// When `force` is true, proceed even if the process identity cannot be
/// verified. Returns `Ok(Some(pid))` if a process was stopped, `Ok(None)` if
/// no running instance was found, or `Err` on unexpected failures.
#[cfg(unix)]
pub fn stop_running_instance(data_dir: &Path, force: bool) -> Result<Option<i32>, StopError> {
    let pid_path = data_dir.join("clawlet.pid");

    let pid_str = match std::fs::read_to_string(&pid_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(StopError::Other(format!(
                "failed to read {}: {e}",
                pid_path.display()
            )))
        }
    };

    let pid: i32 = match pid_str.trim().parse() {
        Ok(p) if p > 0 => p,
        _ => {
            // Corrupt or non-positive PID — remove it.
            let _ = std::fs::remove_file(&pid_path);
            return Ok(None);
        }
    };

    if !process_alive(pid) {
        // Stale PID file.
        let _ = std::fs::remove_file(&pid_path);
        return Ok(None);
    }

    // Verify the process is actually a clawlet instance.
    {
        let verified = verify_is_clawlet(pid);
        match verified {
            VerifyResult::IsClawlet => { /* proceed */ }
            VerifyResult::NotClawlet => {
                // PID was recycled — stale PID file.
                let _ = std::fs::remove_file(&pid_path);
                return Ok(None);
            }
            VerifyResult::CannotVerify => {
                if !force {
                    return Err(StopError::CannotVerify {
                        pid,
                        detail: "neither /proc nor ps could confirm identity".into(),
                    });
                }
                eprintln!("warning: cannot verify PID {pid} is clawlet; proceeding due to --force");
            }
        }
    }

    // Send SIGTERM (race-free when pidfd is available).
    match safe_signal(pid, libc::SIGTERM)? {
        true => { /* sent */ }
        false => {
            // Process already gone.
            let _ = std::fs::remove_file(&pid_path);
            return Ok(None);
        }
    }

    // Wait up to 5 seconds for the process to exit.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if !process_alive(pid) {
            break;
        }
        if Instant::now() >= deadline {
            // Still alive — SIGKILL.
            match safe_signal(pid, libc::SIGKILL) {
                Ok(_) | Err(StopError::Other(_)) => {}
                Err(e) => return Err(e),
            }
            // Brief wait for SIGKILL to take effect.
            thread::sleep(Duration::from_millis(200));
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Only clean up the PID file if the process is truly gone.
    if process_alive(pid) {
        return Err(StopError::StaleProcess { pid });
    }
    let _ = std::fs::remove_file(&pid_path);

    Ok(Some(pid))
}

#[cfg(not(unix))]
pub fn stop_running_instance(_data_dir: &Path, _force: bool) -> Result<Option<i32>, StopError> {
    Err(StopError::Unsupported)
}

/// Run the `stop` subcommand.
pub fn run(data_dir: Option<PathBuf>, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = resolve_data_dir(data_dir)?;
    match stop_running_instance(&data_dir, force)? {
        Some(pid) => {
            eprintln!("Stopped clawlet (PID {pid})");
            Ok(())
        }
        None => {
            eprintln!("No running clawlet found");
            Ok(())
        }
    }
}
