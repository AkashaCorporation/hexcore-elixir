// Linux OS personality
//
// Handles Linux syscalls (x86_64 and ARM64 calling conventions),
// sets up process environment (stack, auxv, brk), and provides
// POSIX API emulation (libc hooks).
//
// Syscall reference: Linux man pages, kernel UAPI headers

use crate::error::ElixirResult;
use crate::os::OsSubsystem;

pub struct LinuxSubsystem {
    // TODO: brk pointer, mmap state, fd table, signal handlers
}

impl LinuxSubsystem {
    pub fn new() -> Self {
        Self {}
    }
}

impl OsSubsystem for LinuxSubsystem {
    fn handle_syscall(&mut self, _number: u64, _args: &[u64]) -> ElixirResult<u64> {
        // TODO: Match syscall number → handler (read, write, open, mmap, brk, exit, etc.)
        todo!("linux syscall dispatch")
    }

    fn setup_process(&mut self) -> ElixirResult<()> {
        // TODO: Stack setup with argc/argv/envp/auxv, brk initialization
        todo!("linux process setup")
    }

    fn resolve_import(&self, _module: &str, _name: &str) -> Option<u64> {
        // TODO: libc function hooks (printf, malloc, etc.)
        None
    }
}
