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

/// Stop a running clawlet instance identified by the PID file in `data_dir`.
///
/// Returns `Ok(Some(pid))` if a process was stopped, `Ok(None)` if no running
/// instance was found, or `Err` on unexpected failures.
#[cfg(unix)]
pub fn stop_running_instance(data_dir: &Path) -> Result<Option<i32>, Box<dyn std::error::Error>> {
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

    // Verify the process is actually a clawlet instance by inspecting
    // /proc/{pid}/cmdline. If it doesn't contain "clawlet", the PID file
    // is stale (recycled PID).
    {
        let cmdline_path = format!("/proc/{pid}/cmdline");
        match std::fs::read(&cmdline_path) {
            Ok(bytes) => {
                // cmdline is NUL-separated; check if any argument contains "clawlet".
                let cmdline = String::from_utf8_lossy(&bytes);
                if !cmdline.contains("clawlet") {
                    let _ = std::fs::remove_file(&pid_path);
                    return Ok(None);
                }
            }
            Err(_) => {
                // Can't read cmdline (process may have exited or /proc unavailable).
                // Treat as stale to be safe.
                let _ = std::fs::remove_file(&pid_path);
                return Ok(None);
            }
        }
    }

    // Send SIGTERM.
    unsafe { libc::kill(pid, libc::SIGTERM) };

    // Wait up to 5 seconds for the process to exit.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if !process_alive(pid) {
            break;
        }
        if Instant::now() >= deadline {
            // Still alive — SIGKILL.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            // Brief wait for SIGKILL to take effect.
            thread::sleep(Duration::from_millis(200));
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Clean up PID file.
    let _ = std::fs::remove_file(&pid_path);

    Ok(Some(pid))
}

#[cfg(not(unix))]
pub fn stop_running_instance(_data_dir: &Path) -> Result<Option<i32>, Box<dyn std::error::Error>> {
    Err("stop is only supported on Unix targets".into())
}

/// Run the `stop` subcommand.
pub fn run(data_dir: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = resolve_data_dir(data_dir)?;
    match stop_running_instance(&data_dir)? {
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
