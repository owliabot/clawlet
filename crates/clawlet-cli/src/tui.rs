//! Secure terminal helpers using crossterm.
//!
//! Provides alternate-screen and raw-mode utilities so that sensitive data
//! (mnemonics, passwords) never appears in terminal scroll-back history.

use std::io::{self, stdout, Write};

use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    style::Print,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};

/// RAII guard that leaves the alternate screen and disables raw mode on drop.
struct AlternateScreenGuard {
    active: bool,
}

impl AlternateScreenGuard {
    fn enter() -> io::Result<Self> {
        execute!(stdout(), EnterAlternateScreen)?;
        Ok(Self { active: true })
    }
}

impl Drop for AlternateScreenGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = execute!(stdout(), LeaveAlternateScreen);
        }
    }
}

/// RAII guard that disables raw mode on drop.
struct RawModeGuard {
    active: bool,
}

impl RawModeGuard {
    fn enable() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        Ok(Self { active: true })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = terminal::disable_raw_mode();
        }
    }
}

/// Run a closure inside an alternate screen buffer.
///
/// The alternate screen is always exited when this function returns, even on
/// error or panic.
pub fn with_alternate_screen<F, T>(f: F) -> Result<T, Box<dyn std::error::Error>>
where
    F: FnOnce() -> Result<T, Box<dyn std::error::Error>>,
{
    let _guard = AlternateScreenGuard::enter()?;
    f()
}

/// Display sensitive text in the alternate screen, wait for Y/y confirmation, then clear.
///
/// The text is only visible while the alternate screen is active. The user must
/// type Y or y to confirm they have saved the content. Once confirmed the
/// screen switches back and no trace remains in scroll-back.
pub fn show_sensitive(lines: &[&str], _footer: &str) -> Result<(), Box<dyn std::error::Error>> {
    with_alternate_screen(|| {
        let mut out = stdout();
        let _raw = RawModeGuard::enable()?;

        // Move to top-left
        execute!(out, cursor::MoveTo(0, 0))?;

        for line in lines {
            execute!(out, Print(line), Print("\r\n"))?;
        }

        let prompt = "⚠️  请确认已保存助记词 (Confirm you have saved the mnemonic)\r\n输入 Y 继续 (Type Y to continue): ";
        let retry = "❌ 请输入 Y 确认已保存助记词 (Please type Y to confirm)\r\n输入 Y 继续 (Type Y to continue): ";

        execute!(out, Print("\r\n"), Print(prompt))?;
        out.flush()?;

        loop {
            if let Event::Key(key_event) = event::read()? {
                match key_event.code {
                    KeyCode::Char('y' | 'Y') => break,
                    KeyCode::Char('c') if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Err("aborted by user".into());
                    }
                    _ => {
                        execute!(out, Print("\r\n"), Print(retry))?;
                        out.flush()?;
                    }
                }
            }
        }

        Ok(())
    })
}
