// HexCore Elixir — Phase 4 Instrumentation Tests
//
// Validates Interceptor, Stalker, DRCOV export, and Snapshot save/restore.
//
// Apache-2.0 licensed. No code copied verbatim.

use elixir_core::emulator::{Emulator, EmulatorConfig};
use elixir_core::types::{Arch, OsType, MemProt};

fn create_bare_emulator() -> Emulator {
    let config = EmulatorConfig {
        arch: Arch::X86_64,
        os: OsType::Bare,
        stack_size: 0x1000,
        heap_size: 0,
        permissive_memory: false,
    };
    Emulator::new(config).expect("Failed to create emulator")
}

// Register constants (from Phase 1 tests)
const UC_X86_REG_RAX: u32 = 35;
const UC_X86_REG_RCX: u32 = 26;
const UC_X86_REG_RIP: u32 = 41;
const UC_X86_REG_RSP: u32 = 44;

#[test]
fn test_stalker_traces_basic_blocks() {
    let mut emu = create_bare_emulator();
    
    // Map code page
    emu.mem_map(0x1000, 0x1000, MemProt::RWX).expect("map code");
    // Map stack
    emu.mem_map(0x2000, 0x1000, MemProt::RW).expect("map stack");
    
    // Write shellcode: mov rax, 0x41; ret
    let shellcode: [u8; 8] = [0x48, 0xc7, 0xc0, 0x41, 0x00, 0x00, 0x00, 0xc3];
    emu.mem_write(0x1000, &shellcode).expect("write");
    
    // Setup registers
    emu.reg_write(UC_X86_REG_RIP, 0x1000).expect("set rip");
    emu.reg_write(UC_X86_REG_RSP, 0x2FF8).expect("set rsp");
    let ret_addr: u64 = 0x1008;
    emu.mem_write(0x2FF8, &ret_addr.to_le_bytes()).expect("write ret");
    
    // Enable stalker BEFORE running
    emu.stalker_follow().expect("stalker follow");
    
    // Run
    emu.run(0x1000, 0x1008, 100).expect("run");
    
    // Check block count
    let blocks = emu.stalker_block_count();
    assert!(blocks > 0, "Stalker should have traced at least 1 block, got {}", blocks);
    
    println!("Stalker traced {} blocks", blocks);
    
    // Unfollow
    emu.stalker_unfollow().expect("unfollow");
}

#[test]
fn test_drcov_export_has_valid_header() {
    let mut emu = create_bare_emulator();
    
    emu.mem_map(0x1000, 0x1000, MemProt::RWX).expect("map");
    emu.mem_map(0x2000, 0x1000, MemProt::RW).expect("map stack");
    
    let shellcode: [u8; 8] = [0x48, 0xc7, 0xc0, 0x41, 0x00, 0x00, 0x00, 0xc3];
    emu.mem_write(0x1000, &shellcode).expect("write");
    emu.reg_write(UC_X86_REG_RIP, 0x1000).expect("rip");
    emu.reg_write(UC_X86_REG_RSP, 0x2FF8).expect("rsp");
    emu.mem_write(0x2FF8, &0x1008u64.to_le_bytes()).expect("ret");
    
    emu.stalker_follow().expect("follow");
    emu.run(0x1000, 0x1008, 100).expect("run");
    
    let drcov = emu.stalker_export_drcov().expect("export drcov");
    assert!(!drcov.is_empty(), "DRCOV data should not be empty");
    
    // Check header starts with "DRCOV VERSION: 2"
    let header = String::from_utf8_lossy(&drcov[..std::cmp::min(50, drcov.len())]);
    assert!(header.starts_with("DRCOV VERSION: 2"), "DRCOV should start with version header, got: {}", header);
    
    println!("DRCOV export: {} bytes", drcov.len());
}

#[test]
fn test_snapshot_save_restore_roundtrip() {
    let mut emu = create_bare_emulator();
    
    // Setup: map memory, write data, set registers
    emu.mem_map(0x1000, 0x1000, MemProt::RWX).expect("map code");
    emu.mem_map(0x2000, 0x1000, MemProt::RW).expect("map stack");
    
    // Write shellcode: mov rax, 0x41; ret
    let shellcode: [u8; 8] = [0x48, 0xc7, 0xc0, 0x41, 0x00, 0x00, 0x00, 0xc3];
    emu.mem_write(0x1000, &shellcode).expect("write");
    
    // Set RAX to a known value
    emu.reg_write(UC_X86_REG_RAX, 0x1234).expect("set rax");
    emu.reg_write(UC_X86_REG_RIP, 0x1000).expect("set rip");
    emu.reg_write(UC_X86_REG_RSP, 0x2FF8).expect("set rsp");
    
    // Save snapshot
    let snapshot = emu.snapshot_save().expect("snapshot save");
    assert!(!snapshot.is_empty(), "Snapshot should not be empty");
    
    // Verify magic header
    assert_eq!(&snapshot[0..7], b"ELXSNAP", "Snapshot should start with ELXSNAP magic");
    
    // Change state
    emu.reg_write(UC_X86_REG_RAX, 0x9999).expect("change rax");
    let changed_rax = emu.reg_read(UC_X86_REG_RAX).expect("read rax");
    assert_eq!(changed_rax, 0x9999, "RAX should be changed");
    
    // Restore snapshot
    emu.snapshot_restore(&snapshot).expect("snapshot restore");
    
    // Verify state restored
    let restored_rax = emu.reg_read(UC_X86_REG_RAX).expect("read rax after restore");
    assert_eq!(restored_rax, 0x1234, "RAX should be restored to original value");
    
    println!("Snapshot roundtrip successful: {} bytes", snapshot.len());
}

#[test]
fn test_interceptor_attach_and_log() {
    let mut emu = create_bare_emulator();
    
    // Map code and stack
    emu.mem_map(0x1000, 0x1000, MemProt::RWX).expect("map code");
    emu.mem_map(0x2000, 0x1000, MemProt::RW).expect("map stack");
    
    // Write a simple function at 0x1000: mov rax, 0x42; ret
    let func_code: [u8; 8] = [0x48, 0xc7, 0xc0, 0x42, 0x00, 0x00, 0x00, 0xc3];
    emu.mem_write(0x1000, &func_code).expect("write func");
    
    // Write caller at 0x1100: call 0x1000 (relative); nop
    // call rel32: E8 xx xx xx xx
    // The offset is: target - (call_addr + 5) = 0x1000 - 0x1105 = -0x105 = 0xFFFFFEFB
    let call_offset: i32 = 0x1000i64.wrapping_sub(0x1105i64) as i32;
    let mut caller_code = vec![0xE8u8];  // CALL rel32
    caller_code.extend_from_slice(&call_offset.to_le_bytes());
    caller_code.push(0xF4); // HLT (stop point)
    emu.mem_write(0x1100, &caller_code).expect("write caller");
    
    // Attach interceptor at the function (0x1000)
    emu.interceptor_attach(0x1000).expect("interceptor attach");
    
    // Setup registers
    emu.reg_write(UC_X86_REG_RIP, 0x1100).expect("set rip");
    emu.reg_write(UC_X86_REG_RSP, 0x2FF0).expect("set rsp");
    
    // Run until HLT or 100 instructions
    let _ = emu.run(0x1100, 0x1106, 100);
    
    // Check interceptor log
    let log_count = emu.interceptor_log_count();
    assert!(log_count > 0, "Interceptor should have logged at least 1 call, got {}", log_count);
    
    println!("Interceptor logged {} calls", log_count);
}
