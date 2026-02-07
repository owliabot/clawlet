//! macOS Keychain integration for password storage.
//!
//! On macOS, we use the `security` CLI to store/retrieve the keystore password.
//! On Linux, we could use `secret-tool` (libsecret) in the future.

#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
const SERVICE_NAME: &str = "clawlet";
#[cfg(target_os = "macos")]
const ACCOUNT_NAME: &str = "keystore";

/// Store password in macOS Keychain.
///
/// Calls: security add-generic-password -U -s clawlet -a keystore -w <password>
pub fn store_password(password: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let status = Command::new("security")
            .args([
                "add-generic-password",
                "-U", // Update if exists
                "-s",
                SERVICE_NAME,
                "-a",
                ACCOUNT_NAME,
                "-w",
                password,
            ])
            .status()
            .map_err(|e| format!("failed to run security command: {e}"))?;

        if !status.success() {
            return Err("failed to store password in Keychain".to_string());
        }
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = password;
        // On non-macOS, silently skip (could add libsecret support later)
        Ok(())
    }
}

/// Retrieve password from macOS Keychain.
///
/// Calls: security find-generic-password -s clawlet -a keystore -w
/// Returns None if not found.
pub fn retrieve_password() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("security")
            .args([
                "find-generic-password",
                "-s",
                SERVICE_NAME,
                "-a",
                ACCOUNT_NAME,
                "-w",
            ])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let password = String::from_utf8(output.stdout).ok()?;
        Some(password.trim().to_string())
    }

    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// Delete password from macOS Keychain.
pub fn delete_password() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let status = Command::new("security")
            .args([
                "delete-generic-password",
                "-s",
                SERVICE_NAME,
                "-a",
                ACCOUNT_NAME,
            ])
            .status()
            .map_err(|e| format!("failed to run security command: {e}"))?;

        // Ignore "not found" errors - status may be non-zero if password doesn't exist
        let _ = status;
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Skip tests on non-macOS or in CI (no Keychain access)
}
