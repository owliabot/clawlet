//! Shared CLI utilities.

use std::io::Write;

/// Display mnemonic, wait for user confirmation, then clear from terminal.
pub fn confirm_and_clear_mnemonic(mnemonic: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("🔑 Generated mnemonic (WRITE THIS DOWN — it will NOT be shown again):");
    eprintln!();
    eprintln!("  {mnemonic}");
    eprintln!();

    loop {
        eprint!("⚠️  Have you saved your mnemonic? Type 'yes' to confirm: ");
        std::io::stderr().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if input.trim().eq_ignore_ascii_case("yes") {
            break;
        }
        eprintln!("   Please type 'yes' to confirm you have saved the mnemonic.");
    }

    // Clear mnemonic from terminal (move up and clear lines)
    // Lines: empty + header + empty + mnemonic + empty + prompt + input = ~7 lines
    let lines_to_clear = 7;
    for _ in 0..lines_to_clear {
        eprint!("\x1B[A\x1B[2K");
    }
    std::io::stderr().flush()?;
    eprintln!("✅ Mnemonic confirmed and cleared from screen");

    Ok(())
}
