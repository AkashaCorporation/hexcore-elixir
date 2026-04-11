// Windows OS personality
//
// Emulates the Windows user-mode environment:
// - PEB/TEB setup
// - NTDLL syscall dispatch
// - Kernel32/KernelBase/User32 API hooks
// - Registry emulation (via VFS)
// - Heap manager (RtlAllocateHeap, etc.)
//
// Behavior reference: MSDN, ReactOS (LGPL, study only), Wine (LGPL, study only)
// NO CODE COPIED from any GPL/LGPL source — clean-room from specs.

use crate::error::ElixirResult;
use crate::os::OsSubsystem;

pub struct WindowsSubsystem {
    // TODO: PEB/TEB addresses, loaded modules list, heap state, registry VFS
}

impl WindowsSubsystem {
    pub fn new() -> Self {
        Self {}
    }
}

impl OsSubsystem for WindowsSubsystem {
    fn handle_syscall(&mut self, _number: u64, _args: &[u64]) -> ElixirResult<u64> {
        // TODO: NTDLL syscall dispatch (NtCreateFile, NtAllocateVirtualMemory, etc.)
        todo!("windows syscall dispatch")
    }

    fn setup_process(&mut self) -> ElixirResult<()> {
        // TODO: PEB/TEB creation, module list (LDR_DATA_TABLE_ENTRY),
        //       default heap, process parameters
        todo!("windows process setup")
    }

    fn resolve_import(&self, _module: &str, _name: &str) -> Option<u64> {
        // TODO: Hook table for kernel32, ntdll, user32, etc.
        None
    }
}
