//! Parity Gate G4: Clean MSVC Hello World terminates in <100,000 instructions via exit()

use elixir_core::emulator::{Emulator, EmulatorConfig};
use elixir_core::types::{Arch, OsType, SimpleStopReason};

// Unicorn x86_64 register IDs (from unicorn/x86.h)
const UC_X86_REG_RAX: u32 = 35;
const UC_X86_REG_RIP: u32 = 41;
const UC_X86_REG_RSP: u32 = 44;

#[test]
fn parity_gate_g4_msvc_hello_world() {
    let binary = std::fs::read("../../tests/fixtures/hello_msvc.exe")
        .expect("Failed to read hello_msvc.exe - compile with: cl /EHsc /O2 /MT hello_world.cpp");
    
    let config = EmulatorConfig {
        arch: Arch::X86_64,
        os: OsType::Windows,
        permissive_memory: true,
        ..Default::default()
    };
    let mut emu = Emulator::new(config).expect("Failed to create emulator");
    
    // Enable permissive memory mode in the engine
    emu.set_permissive_memory(true).expect("Failed to set permissive memory");
    
    let entry = emu.load(&binary).expect("Failed to load PE binary");
    println!("G4: Entry point = 0x{:x}", entry);
    
    // Debug: read RIP before running
    let rip_before = emu.reg_read(UC_X86_REG_RIP).unwrap_or(0xFFFFFFFF);
    let rsp_before = emu.reg_read(UC_X86_REG_RSP).unwrap_or(0);
    println!("G4: Before run: RIP = 0x{:016x}, RSP = 0x{:016x}", rip_before, rsp_before);
    
    // Run with 100k instruction limit — G4 requires termination WITHIN this
    let result = emu.run(entry, 0, 100_000);
    println!("G4: run() returned {:?}", result);
    
    // Check stop reason
    let reason = emu.stop_reason();
    println!("G4: Stop reason = {:?}", reason);
    
    // Check API call count
    let api_count = emu.api_log_count();
    println!("G4: {} API calls captured", api_count);
    
    // Read RIP and RSP for debugging
    let rip = emu.reg_read(UC_X86_REG_RIP).unwrap_or(0);
    let rsp = emu.reg_read(UC_X86_REG_RSP).unwrap_or(0);
    let rax = emu.reg_read(UC_X86_REG_RAX).unwrap_or(0);
    println!("G4: RIP = 0x{:016x}, RSP = 0x{:016x}, RAX = 0x{:016x}", rip, rsp, rax);
    
    // Determine if RIP is in stub region (0x70000000+)
    if rip >= 0x70000000 && rip < 0x70100000 {
        println!("G4: RIP is in STUB region - unhandled import called");
    }
    
    // Check stalker block count
    let block_count = emu.stalker_block_count();
    println!("G4: {} basic blocks traced", block_count);
    
    // Export DRCov for analysis if blocks were traced
    if block_count > 0 && block_count < 500000 {
        match emu.stalker_export_drcov() {
            Ok(data) => {
                // Save to file for analysis
                let cwd = std::env::current_dir().expect("Failed to get cwd");
                let drcov_path = cwd.join("../../../target/g4_drcov.log");
                match std::fs::write(&drcov_path, &data) {
                    Ok(_) => println!("G4: DRCov exported to {:?}", drcov_path),
                    Err(e) => println!("G4: Failed to write DRCov: {}", e),
                }
            }
            Err(e) => println!("G4: Failed to export DRCov: {:?}", e),
        }
    }
    
    // G4 PASS CRITERIA:
    // 1. Must exit cleanly (not hit instruction limit)
    assert_eq!(reason, SimpleStopReason::Exit,
        "G4 FAILED: Expected clean exit in <100k insns, got {:?}", reason);
    
    // 2. API hooks should fire (CRT init at minimum)
    assert!(api_count > 0, "G4 FAILED: No API hooks fired");
    
    println!("=== G4 PASSED === ({} API calls, clean exit in <100k insns)", api_count);
}
