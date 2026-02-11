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

/// Display sensitive text in the alternate screen, wait for Enter, then clear.
///
/// The text is only visible while the alternate screen is active. Once the user
/// presses Enter the screen switches back and no trace remains in scroll-back.
pub fn show_sensitive(lines: &[&str], footer: &str) -> Result<(), Box<dyn std::error::Error>> {
    with_alternate_screen(|| {
        let mut out = stdout();
        let _raw = RawModeGuard::enable()?;

        // Move to top-left
        execute!(out, cursor::MoveTo(0, 0))?;

        for line in lines {
            execute!(out, Print(line), Print("\r\n"))?;
        }
        execute!(out, Print("\r\n"), Print(footer), Print("\r\n"))?;
        out.flush()?;

        // Wait for Enter or Ctrl+C
        loop {
            if let Event::Key(key_event) = event::read()? {
                match key_event.code {
                    KeyCode::Enter => break,
                    KeyCode::Char('c') if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
                        break
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    })
}
