// HexCore Elixir — Phase 1.1 Sanity Test
//
// Validates basic Unicorn wiring: create engine, map memory,
// write/execute x86_64 shellcode, read register result.
//
// Apache-2.0 licensed. No code copied verbatim.

use elixir_core::emulator::{Emulator, EmulatorConfig};
use elixir_core::types::{Arch, OsType, MemProt};

// Register IDs from Unicorn x86.h
// Enum values calculated from the C enum:
// UC_X86_REG_RAX = 35
// UC_X86_REG_RIP = 41
// UC_X86_REG_RSP = 44
const UC_X86_REG_RAX: u32 = 35;
const UC_X86_REG_RIP: u32 = 41;
const UC_X86_REG_RSP: u32 = 44;

#[test]
fn phase1_mov_rax_ret() {
    // 1. Create emulator for x86_64 bare-metal
    let config = EmulatorConfig {
        arch: Arch::X86_64,
        os: OsType::Bare,
        stack_size: 0x1000,
        heap_size: 0,
        permissive_memory: false,
    };
    let mut emu = Emulator::new(config).expect("Failed to create emulator");

    // 2. Map code page at 0x1000 (4 KB, RWX)
    emu.mem_map(0x1000, 0x1000, MemProt::RWX)
        .expect("Failed to map code page");

    // 3. Map stack page at 0x2000 (4 KB, RW)
    emu.mem_map(0x2000, 0x1000, MemProt::RW)
        .expect("Failed to map stack page");

    // 4. Write shellcode: mov rax, 0x41; ret
    let shellcode: [u8; 8] = [0x48, 0xc7, 0xc0, 0x41, 0x00, 0x00, 0x00, 0xc3];
    emu.mem_write(0x1000, &shellcode)
        .expect("Failed to write shellcode");

    // Verify shellcode was written correctly
    let mut read_back = [0u8; 8];
    emu.mem_read(0x1000, &mut read_back).expect("Failed to read back shellcode");
    assert_eq!(read_back, shellcode, "Shellcode read-back mismatch");

    // 5. Set registers: rip = 0x1000, rsp = top of stack page
    emu.reg_write(UC_X86_REG_RIP, 0x1000).expect("Failed to set RIP");
    emu.reg_write(UC_X86_REG_RSP, 0x2FF0).expect("Failed to set RSP");

    // Verify registers were set
    let rip = emu.reg_read(UC_X86_REG_RIP).expect("Failed to read RIP");
    let rsp = emu.reg_read(UC_X86_REG_RSP).expect("Failed to read RSP");
    assert_eq!(rip, 0x1000, "RIP not set correctly");
    assert_eq!(rsp, 0x2FF0, "RSP not set correctly");

    // 6. Run until 0x1008 (end of shellcode) or max 100 instructions
    // Note: For the ret instruction to work, we need a valid return address on the stack
    // Let's write a return address to the stack
    let return_addr: u64 = 0x1008; // Address after ret
    let return_addr_bytes = return_addr.to_le_bytes();
    emu.mem_write(0x2FF0, &return_addr_bytes).expect("Failed to write return address");

    let result = emu.run(0x1000, 0x1008, 100);
    match &result {
        Ok(stop_reason) => println!("Emulation stopped: {:?}", stop_reason),
        Err(e) => println!("Emulation error: {:?}", e),
    }
    result.expect("Emulation failed");

    // 7. Read RAX and verify
    let rax = emu.reg_read(UC_X86_REG_RAX).expect("Failed to read RAX");
    println!("RAX = 0x{:x}", rax);
    assert_eq!(rax, 0x41, "RAX should be 0x41 after mov rax, 0x41; ret");
}

#[test]
fn test_double_map_same_region() {
    // Create emulator, map a page, then try to map the same page again
    // Second map should fail (overlap detection)
    let config = EmulatorConfig { arch: Arch::X86_64, os: OsType::Bare, stack_size: 0x1000, heap_size: 0, permissive_memory: false };
    let mut emu = Emulator::new(config).expect("Failed to create emulator");
    
    emu.mem_map(0x1000, 0x1000, MemProt::RWX).expect("First map should succeed");
    let result = emu.mem_map(0x1000, 0x1000, MemProt::RWX);
    assert!(result.is_err(), "Second map of same region should fail");
}

#[test]
fn test_mem_write_read_roundtrip() {
    let config = EmulatorConfig { arch: Arch::X86_64, os: OsType::Bare, stack_size: 0x1000, heap_size: 0, permissive_memory: false };
    let mut emu = Emulator::new(config).expect("Failed to create emulator");
    
    emu.mem_map(0x5000, 0x1000, MemProt::RW).expect("Map should succeed");
    
    let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
    emu.mem_write(0x5000, &data).expect("Write should succeed");
    
    let mut buf = vec![0u8; 256];
    emu.mem_read(0x5000, &mut buf).expect("Read should succeed");
    assert_eq!(data, buf, "Read data should match written data");
}

#[test]
fn test_permissive_memory_auto_map() {
    // Create emulator, enable permissive mode, write to unmapped address
    // The fault handler should auto-map the page and allow the write
    let config = EmulatorConfig { arch: Arch::X86_64, os: OsType::Bare, stack_size: 0x1000, heap_size: 0, permissive_memory: false };
    let mut emu = Emulator::new(config).expect("Failed to create emulator");
    
    // Enable permissive memory
    emu.set_permissive_memory(true).expect("Should enable permissive mode");
    
    // Map code page and write shellcode that writes to unmapped address 0x50000
    // Shellcode: mov qword [0x50000], 0x42; ret
    // Actually, let's use a simpler approach: map code, write shellcode that does:
    //   mov rax, 0x50000
    //   mov qword ptr [rax], 0x42
    //   ret
    emu.mem_map(0x1000, 0x1000, MemProt::RWX).expect("Map code page");
    emu.mem_map(0x2000, 0x1000, MemProt::RW).expect("Map stack page");
    
    // Shellcode: mov rax, 0x50000; mov dword [rax], 0x42; ret
    // 48 c7 c0 00 00 05 00    mov rax, 0x50000
    // c7 00 42 00 00 00        mov dword [rax], 0x42
    // c3                       ret
    let shellcode: [u8; 14] = [
        0x48, 0xc7, 0xc0, 0x00, 0x00, 0x05, 0x00,  // mov rax, 0x50000
        0xc7, 0x00, 0x42, 0x00, 0x00, 0x00,          // mov dword [rax], 0x42
        0xc3                                           // ret
    ];
    emu.mem_write(0x1000, &shellcode).expect("Write shellcode");
    
    // Set up registers
    // UC_X86_REG_RIP = 41, UC_X86_REG_RSP = 44
    emu.reg_write(UC_X86_REG_RIP, 0x1000).expect("Set RIP");
    emu.reg_write(UC_X86_REG_RSP, 0x2FF0).expect("Set RSP");
    
    // Write return address on stack
    emu.mem_write(0x2FF0, &0x100E_u64.to_le_bytes()).expect("Write return addr");
    
    // Run - this should NOT crash because permissive mode auto-maps 0x50000
    let result = emu.run(0x1000, 0x100E, 100);
    assert!(result.is_ok(), "Emulation should succeed with permissive memory: {:?}", result);
    
    // Verify the write happened
    let mut buf = [0u8; 4];
    emu.mem_read(0x50000, &mut buf).expect("Should be able to read auto-mapped page");
    assert_eq!(u32::from_le_bytes(buf), 0x42, "Value at 0x50000 should be 0x42");
}
