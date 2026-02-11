//! Shared CLI utilities.

use std::io::{IsTerminal, Write};

/// Display mnemonic, wait for user confirmation, then clear from terminal.
pub fn confirm_and_clear_mnemonic(mnemonic: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("🔑 Generated mnemonic (WRITE THIS DOWN — it will NOT be shown again):");
    eprintln!();
    eprintln!("  {mnemonic}");
    eprintln!();

    // Track lines to clear: empty + header + empty + mnemonic + empty = 5
    let mut lines_to_clear = 5;

    loop {
        eprint!("⚠️  Have you saved your mnemonic? Type 'yes' to confirm: ");
        std::io::stderr().flush()?;

        let mut input = String::new();
        let bytes_read = std::io::stdin().read_line(&mut input)?;

        // Check for EOF
        if bytes_read == 0 {
            return Err("Unexpected EOF while waiting for mnemonic confirmation".into());
        }

        // Count this line (prompt + input)
        lines_to_clear += 1;

        if input.trim().eq_ignore_ascii_case("yes") {
            break;
        }
        eprintln!("   Please type 'yes' to confirm you have saved the mnemonic.");
        // Count the rejection message line
        lines_to_clear += 1;
    }

    // Clear mnemonic from terminal (move up and clear lines) - only if stderr is a terminal
    if std::io::stderr().is_terminal() {
        for _ in 0..lines_to_clear {
            eprint!("\x1B[A\x1B[2K");
        }
        std::io::stderr().flush()?;
    }
    eprintln!("✅ Mnemonic confirmed and cleared from screen");

    Ok(())
}
