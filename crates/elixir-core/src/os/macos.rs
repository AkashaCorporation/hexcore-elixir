// macOS OS personality
//
// Handles Mach syscalls, BSD syscall layer, and dyld emulation.
// Lower priority than Linux/Windows — stub for now.

use crate::error::ElixirResult;
use crate::os::OsSubsystem;

pub struct MacOsSubsystem;

impl MacOsSubsystem {
    pub fn new() -> Self {
        Self
    }
}

impl OsSubsystem for MacOsSubsystem {
    fn handle_syscall(&mut self, _number: u64, _args: &[u64]) -> ElixirResult<u64> {
        todo!("macos syscall dispatch")
    }

    fn setup_process(&mut self) -> ElixirResult<()> {
        todo!("macos process setup")
    }

    fn resolve_import(&self, _module: &str, _name: &str) -> Option<u64> {
        None
    }
}
