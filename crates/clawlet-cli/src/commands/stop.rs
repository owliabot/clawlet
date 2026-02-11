//! `clawlet stop` — stop a running clawlet daemon.
//!
//! Reads the PID file, sends SIGTERM, waits up to 5 seconds, then SIGKILL
//! if needed. Shared helper [`stop_running_instance`] is reused by `start`.

use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

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

/// Verify that the given PID belongs to a clawlet process.
///
/// Tries `/proc/{pid}/cmdline` first (Linux), then falls back to
/// `ps -p {pid} -o comm=` which works on both Linux and macOS.
fn verify_is_clawlet(pid: i32) -> VerifyResult {
    // Try procfs first.
    let cmdline_path = format!("/proc/{pid}/cmdline");
    if let Ok(bytes) = std::fs::read(&cmdline_path) {
        let cmdline = String::from_utf8_lossy(&bytes);
        return if cmdline.contains("clawlet") {
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
            if comm.contains("clawlet") {
                VerifyResult::IsClawlet
            } else {
                VerifyResult::NotClawlet
            }
        }
        _ => VerifyResult::CannotVerify,
    }
}

/// Stop a running clawlet instance identified by the PID file in `data_dir`.
///
/// When `force` is true, proceed even if the process identity cannot be
/// verified. Returns `Ok(Some(pid))` if a process was stopped, `Ok(None)` if
/// no running instance was found, or `Err` on unexpected failures.
#[cfg(unix)]
pub fn stop_running_instance(
    data_dir: &Path,
    force: bool,
) -> Result<Option<i32>, Box<dyn std::error::Error>> {
    let pid_path = data_dir.join("clawlet.pid");

    let pid_str = match std::fs::read_to_string(&pid_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("failed to read {}: {e}", pid_path.display()).into()),
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
    // First try /proc/{pid}/cmdline (Linux), then fall back to `ps` (works
    // on both Linux and macOS).
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
                    return Err(format!(
                        "cannot verify that PID {pid} is a clawlet process; \
                         use --force to stop it anyway, or kill it manually"
                    )
                    .into());
                }
                eprintln!("warning: cannot verify PID {pid} is clawlet; proceeding due to --force");
            }
        }
    }

    // Send SIGTERM and check the return value.
    let ret = unsafe { libc::kill(pid, libc::SIGTERM) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            // Process already gone.
            let _ = std::fs::remove_file(&pid_path);
            return Ok(None);
        }
        // EPERM or other error — cannot stop.
        return Err(format!("failed to send SIGTERM to PID {pid}: {err}").into());
    }

    // Wait up to 5 seconds for the process to exit.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if !process_alive(pid) {
            break;
        }
        if Instant::now() >= deadline {
            // Still alive — SIGKILL.
            let ret = unsafe { libc::kill(pid, libc::SIGKILL) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ESRCH) {
                    return Err(format!("failed to send SIGKILL to PID {pid}: {err}").into());
                }
            }
            // Brief wait for SIGKILL to take effect.
            thread::sleep(Duration::from_millis(200));
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Only clean up the PID file if the process is truly gone.
    if process_alive(pid) {
        return Err(
            format!("PID {pid} is still alive after SIGKILL; not removing PID file").into(),
        );
    }
    let _ = std::fs::remove_file(&pid_path);

    Ok(Some(pid))
}

#[cfg(not(unix))]
pub fn stop_running_instance(
    _data_dir: &Path,
    _force: bool,
) -> Result<Option<i32>, Box<dyn std::error::Error>> {
    Err("stop is only supported on Unix targets".into())
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
