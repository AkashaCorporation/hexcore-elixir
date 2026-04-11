// elixir_core — OS Subsystem
//
// Tier 3 (elixir_os): The OS personality layer.
// Traps syscalls/interrupts and routes them to POSIX or Win32 handlers.
//
// Clean-room implementation — no Qiling code, no GPL code.
// Behavior references: MSDN, ReactOS (LGPL, study only), Linux man pages.

pub mod linux;
pub mod windows;
pub mod macos;

use crate::error::ElixirResult;
use crate::types::{Arch, OsType};

/// Trait that each OS personality implements
pub trait OsSubsystem {
    /// Handle a syscall/interrupt
    fn handle_syscall(&mut self, number: u64, args: &[u64]) -> ElixirResult<u64>;

    /// Set up the initial process environment (stack, PEB/TEB, aux vectors, etc.)
    fn setup_process(&mut self) -> ElixirResult<()>;

    /// Resolve an imported function name to a hook address
    fn resolve_import(&self, module: &str, name: &str) -> Option<u64>;
}

/// Create the appropriate OS subsystem for the given configuration
pub fn create_subsystem(_os: OsType, _arch: Arch) -> ElixirResult<Box<dyn OsSubsystem>> {
    todo!("subsystem factory")
}
