//! Hide the console window of child processes on Windows.
//!
//! Maestro is a GUI-subsystem app, so it has no console of its own. When it
//! spawns a console program (`docker.exe`, `git`, `cmd`, `taskkill`, ...)
//! Windows gives that child a brand-new console window unless the
//! `CREATE_NO_WINDOW` creation flag is set. On Windows 11 that console is
//! hosted by Windows Terminal, so every background status poll (Docker state,
//! Claude auth check, tmux session listing) flashed a Terminal window on top of
//! the app and stole keyboard focus.
//!
//! Call `.no_window()` on every `std::process::Command` / `tokio::process::Command`
//! right after `Command::new(..)`. It is a no-op on macOS and Linux.

/// `CREATE_NO_WINDOW` from the Win32 process creation flags.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub trait NoWindow {
    /// Spawn the child without a console window (Windows only; no-op elsewhere).
    fn no_window(&mut self) -> &mut Self;
}

impl NoWindow for std::process::Command {
    fn no_window(&mut self) -> &mut Self {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            self.creation_flags(CREATE_NO_WINDOW);
        }
        self
    }
}

impl NoWindow for tokio::process::Command {
    fn no_window(&mut self) -> &mut Self {
        #[cfg(windows)]
        {
            self.creation_flags(CREATE_NO_WINDOW);
        }
        self
    }
}
