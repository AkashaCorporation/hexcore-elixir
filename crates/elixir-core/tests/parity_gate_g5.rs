//! Parity Gate G5: mali_kbase.ko (ELF x86_64 kernel module) loads and executes kbase_jit_allocate
//!
//! This test verifies the ELF ET_REL loader and Linux kernel API stub system:
//! - Loads a Linux kernel module (.ko) as ET_REL
//! - Resolves ~343 external kernel symbols to stubs
//! - Applies relocations
//! - Executes kbase_jit_allocate function
//! - Passes if no fault occurs during execution

use elixir_core::emulator::{Emulator, EmulatorConfig};
use elixir_core::types::{Arch, OsType, SimpleStopReason};

// Unicorn x86_64 register IDs (from unicorn/x86.h)
const UC_X86_REG_RAX: u32 = 35;
const UC_X86_REG_RIP: u32 = 41;
const UC_X86_REG_RSP: u32 = 44;
const UC_X86_REG_RDI: u32 = 39;

#[test]
fn parity_gate_g5_mali_kbase_ko() {
    // Load the kernel module fixture
    let binary = std::fs::read("../../tests/fixtures/mali_kbase.ko")
        .expect("Failed to read mali_kbase.ko fixture");
    
    println!("G5: mali_kbase.ko loaded ({} bytes)", binary.len());
    
    // Create emulator for Linux kernel module emulation
    let config = EmulatorConfig {
        arch: Arch::X86_64,
        os: OsType::Linux,
        permissive_memory: true,
        ..Default::default()
    };
    let mut emu = Emulator::new(config).expect("Failed to create emulator");
    
    // Enable permissive memory mode (auto-map on fault)
    emu.set_permissive_memory(true).expect("Failed to set permissive memory");
    
    // Load ELF ET_REL — entry point should be kbase_jit_allocate
    let entry = emu.load(&binary).expect("Failed to load ELF ET_REL");
    println!("G5: Entry point (kbase_jit_allocate) = 0x{:x}", entry);
    
    // Debug: read RIP and RSP before running
    let rip_before = emu.reg_read(UC_X86_REG_RIP).unwrap_or(0xFFFFFFFF);
    let rsp_before = emu.reg_read(UC_X86_REG_RSP).unwrap_or(0);
    let rdi_before = emu.reg_read(UC_X86_REG_RDI).unwrap_or(0);
    println!("G5: Before run: RIP = 0x{:016x}, RSP = 0x{:016x}, RDI = 0x{:016x}", 
             rip_before, rsp_before, rdi_before);
    
    // Run with 1M instruction limit
    let max_insns = 1_000_000;
    let result = emu.run(entry, 0, max_insns);
    println!("G5: run() returned {:?}", result);
    
    // Check stop reason
    let reason = emu.stop_reason();
    println!("G5: Stop reason = {:?}", reason);
    
    // Debug: read RIP and RAX after running
    let rip = emu.reg_read(UC_X86_REG_RIP).unwrap_or(0);
    let rsp = emu.reg_read(UC_X86_REG_RSP).unwrap_or(0);
    let rax = emu.reg_read(UC_X86_REG_RAX).unwrap_or(0);
    println!("G5: After run: RIP = 0x{:016x}, RSP = 0x{:016x}, RAX = 0x{:016x}", 
             rip, rsp, rax);
    
    // Determine if RIP is in stub region (0x72000000+)
    if rip >= 0x72000000 && rip < 0x72100000 {
        println!("G5: RIP is in Linux stub region - kernel stub called");
    }
    
    // G5 PASS CRITERIA: execution without fault
    // The test passes if:
    // 1. The ELF ET_REL file was loaded successfully
    // 2. Execution started and did not result in an Error stop reason
    // Note: InsnLimit is OK (function may loop calling stubs)
    //       Exit is also OK (if the function returns via syscall)
    assert_ne!(reason, SimpleStopReason::Error,
        "G5 FAILED: fault during execution of kbase_jit_allocate (RIP=0x{:016x})", rip);
    
    println!("=== G5 PASSED === (stop_reason={:?}, entry=0x{:x})", reason, entry);
}
