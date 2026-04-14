use bitflags::bitflags;
use serde::{Deserialize, Serialize};

/// Supported CPU architectures
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Arm64,
}

/// Target operating system personality
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsType {
    Linux,
    Windows,
    MacOS,
    /// Bare metal — no OS emulation, just CPU + memory
    Bare,
}

/// Binary format detected by the loader
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    PE,
    ELF,
    MachO,
    Raw,
}

bitflags! {
    /// Memory protection flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MemProt: u32 {
        const NONE  = 0;
        const READ  = 1;
        const WRITE = 2;
        const EXEC  = 4;
        const RW    = Self::READ.bits() | Self::WRITE.bits();
        const RX    = Self::READ.bits() | Self::EXEC.bits();
        const RWX   = Self::READ.bits() | Self::WRITE.bits() | Self::EXEC.bits();
    }
}

/// A mapped memory region
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub prot: u32,
    pub name: String,
}

/// CPU context snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuContext {
    pub arch: Arch,
    pub registers: Vec<(u32, u64)>,
}

/// Full emulation state (CPU + memory)
#[derive(Debug, Clone)]
pub struct EmulationState {
    pub cpu: CpuContext,
    pub regions: Vec<(MemoryRegion, Vec<u8>)>,
}

/// Hook types for the instrumentation layer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookType {
    /// Fire before a function executes
    FunctionEntry,
    /// Fire after a function returns
    FunctionExit,
    /// Fire on every basic block
    BasicBlock,
    /// Fire on memory read
    MemoryRead,
    /// Fire on memory write
    MemoryWrite,
    /// Fire on syscall/interrupt
    Syscall,
}

/// Emulation stop reason (detailed, for backward compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StopReason {
    /// Reached end address
    EndAddress(u64),
    /// Hit a breakpoint
    Breakpoint(u64),
    /// Unhandled syscall
    Syscall { number: u64, arch: Arch },
    /// Memory fault
    MemoryFault { addr: u64, access: String },
    /// Instruction limit reached
    InstructionLimit(u64),
    /// Agent requested stop
    AgentStop(String),
    /// Error during emulation
    Error(String),
}

/// Simple stop reason enum — matches C ElixirStopReason
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimpleStopReason {
    None = 0,
    Exit = 1,
    InsnLimit = 2,
    Error = 3,
    User = 4,
}
