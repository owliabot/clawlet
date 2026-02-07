use crate::commands::daemon::{is_pid_alive, read_daemon_state};

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let state = match read_daemon_state() {
        Ok(state) => state,
        Err(err) => {
            if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
                if io_err.kind() == std::io::ErrorKind::NotFound {
                    println!("Status: stopped");
                    println!("PID: -");
                    println!("Wallet: -");
                    println!("Session token: -");
                    return Ok(());
                }
            }
            return Err(err);
        }
    };

    let running = is_pid_alive(state.pid);
    let status = if running { "running" } else { "stopped" };

    println!("Status: {status}");
    println!("PID: {}", state.pid);
    println!("Wallet: {}", state.wallet_address);
    println!("Session token: {}", state.token);

    Ok(())
}
