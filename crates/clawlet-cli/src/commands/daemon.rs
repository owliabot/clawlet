use std::path::PathBuf;

use chrono::{DateTime, Utc};
use clawlet_core::fs::write_secure;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonState {
    pub pid: i32,
    pub token: String,
    pub wallet_address: String,
    pub started_at: DateTime<Utc>,
}

pub fn daemon_state_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    Ok(home.join(".clawlet").join("daemon.json"))
}

pub fn write_daemon_state(state: &DaemonState) -> Result<(), Box<dyn std::error::Error>> {
    let path = daemon_state_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let payload = serde_json::to_vec_pretty(state)?;
    write_secure(&path, payload)?;
    Ok(())
}

pub fn read_daemon_state() -> Result<DaemonState, Box<dyn std::error::Error>> {
    let path = daemon_state_path()?;
    let payload = std::fs::read(path)?;
    Ok(serde_json::from_slice(&payload)?)
}

#[cfg(unix)]
pub fn is_pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }

    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }

    matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    )
}

#[cfg(not(unix))]
pub fn is_pid_alive(_pid: i32) -> bool {
    false
}
