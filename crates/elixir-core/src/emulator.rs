// elixir_core — Emulator
//
// The main emulation context. Manages CPU state, memory, and the execution loop.
// In Rust-only mode, this drives HexCore-Unicorn through its existing API.
// When the C++ engine is linked, this delegates to the native engine via FFI.

use crate::error::ElixirResult;
use crate::types::{Arch, OsType, StopReason};

/// Configuration for creating an Elixir emulation session
#[derive(Debug, Clone)]
pub struct EmulatorConfig {
    pub arch: Arch,
    pub os: OsType,
    pub stack_size: u64,
    pub heap_size: u64,
    /// Enable permissive memory mapping (auto-map on fault)
    pub permissive_memory: bool,
}

impl Default for EmulatorConfig {
    fn default() -> Self {
        Self {
            arch: Arch::X86_64,
            os: OsType::Linux,
            stack_size: 2 * 1024 * 1024,   // 2 MB
            heap_size: 16 * 1024 * 1024,    // 16 MB
            permissive_memory: false,
        }
    }
}

/// The main emulation context
pub struct Emulator {
    pub config: EmulatorConfig,
    // TODO: Unicorn engine handle, memory manager, OS subsystem, hooks
}

impl Emulator {
    /// Create a new emulation context
    pub fn new(config: EmulatorConfig) -> ElixirResult<Self> {
        Ok(Self { config })
    }

    /// Load a binary into the emulator
    pub fn load(&mut self, _data: &[u8]) -> ElixirResult<u64> {
        // TODO: Detect format (PE/ELF/MachO), invoke loader, return entry point
        todo!("loader integration")
    }

    /// Start emulation from the given address
    pub fn run(&mut self, _start: u64, _end: u64, _max_insns: u64) -> ElixirResult<StopReason> {
        todo!("emulation loop")
    }

    /// Stop emulation
    pub fn stop(&mut self) -> ElixirResult<()> {
        todo!("stop")
    }

    /// Save a full snapshot of the emulation state
    pub fn snapshot_save(&self) -> ElixirResult<Vec<u8>> {
        todo!("snapshot save")
    }

    /// Restore from a snapshot
    pub fn snapshot_restore(&mut self, _data: &[u8]) -> ElixirResult<()> {
        todo!("snapshot restore")
    }
}
