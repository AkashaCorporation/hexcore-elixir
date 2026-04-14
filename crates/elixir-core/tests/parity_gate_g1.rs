//! Parity Gate G1: Malware HexCore Defeat v1 exits cleanly via exit()/ExitProcess()

use elixir_core::emulator::{Emulator, EmulatorConfig};
use elixir_core::types::{Arch, OsType, SimpleStopReason};

// Unicorn x86_64 register IDs (from unicorn/x86.h)
const UC_X86_REG_RAX: u32 = 35;
const UC_X86_REG_RIP: u32 = 41;
const UC_X86_REG_RSP: u32 = 44;

#[test]
fn parity_gate_g1_malware_v1_exits_cleanly() {
    // Load the test binary
    let binary = std::fs::read("../../tests/fixtures/Malware HexCore Defeat.exe")
        .expect("Failed to read test fixture - ensure tests/fixtures/Malware HexCore Defeat.exe exists");
    
    // Create emulator with permissive memory (tolerate unmapped reads)
    let config = EmulatorConfig {
        arch: Arch::X86_64,
        os: OsType::Windows,
        permissive_memory: true,
        ..Default::default()
    };
    let mut emu = Emulator::new(config).expect("Failed to create emulator");
    
    // Enable permissive memory mode in the engine
    emu.set_permissive_memory(true).expect("Failed to set permissive memory");
    
    // Load the PE binary
    let entry = emu.load(&binary).expect("Failed to load PE binary");
    println!("G1: Entry point = 0x{:x}", entry);
    
    // Debug: read RIP before running
    let rip_before = emu.reg_read(UC_X86_REG_RIP).unwrap_or(0xFFFFFFFF);
    let rsp_before = emu.reg_read(UC_X86_REG_RSP).unwrap_or(0);
    println!("G1: Before run: RIP = 0x{:016x}, RSP = 0x{:016x}", rip_before, rsp_before);
    
    // Enable stalker to trace execution
    // emu.stalker_follow().expect("Failed to enable stalker");
    
    // Run with high instruction limit (10M) — we expect exit() BEFORE this
    let max_insns = 10_000_000; // 10M
    let result = emu.run(entry, 0, max_insns);
    println!("G1: run() returned {:?}", result);
    
    // Check stop reason
    let reason = emu.stop_reason();
    println!("G1: Stop reason = {:?}", reason);
    
    // Check API call count
    let api_count = emu.api_log_count();
    println!("G1: {} API calls captured", api_count);
    
    // Read RIP and RSP for debugging
    let rip = emu.reg_read(UC_X86_REG_RIP).unwrap_or(0);
    let rsp = emu.reg_read(UC_X86_REG_RSP).unwrap_or(0);
    let rax = emu.reg_read(UC_X86_REG_RAX).unwrap_or(0);
    println!("G1: RIP = 0x{:016x}, RSP = 0x{:016x}, RAX = 0x{:016x}", rip, rsp, rax);
    
    // Determine if RIP is in stub region (0x70000000+)
    if rip >= 0x70000000 && rip < 0x70100000 {
        println!("G1: RIP is in STUB region - unhandled import called");
    }
    
    // Check stalker block count
    let block_count = emu.stalker_block_count();
    println!("G1: {} basic blocks traced", block_count);
    
    // Export DRCov for analysis if many blocks
    if block_count > 0 && block_count < 500000 {
        match emu.stalker_export_drcov() {
            Ok(data) => {
                // Save to file for analysis - use absolute path from workspace root
                let cwd = std::env::current_dir().expect("Failed to get cwd");
                println!("G1: Current directory: {:?}", cwd);
                let drcov_path = cwd.join("../../../target/g1_drcov.log");
                println!("G1: DRCov path: {:?}", drcov_path);
                match std::fs::write(&drcov_path, &data) {
                    Ok(_) => println!("G1: DRCov exported to {:?}", drcov_path),
                    Err(e) => println!("G1: Failed to write DRCov: {}", e),
                }
            }
            Err(e) => println!("G1: Failed to export DRCov: {:?}", e),
        }
    }
    
    // G1 PASS CRITERIA:
    // 1. Stop reason must be Exit (clean exit via exit()/ExitProcess())
    assert_eq!(reason, SimpleStopReason::Exit, 
        "G1 FAILED: Expected clean exit, got {:?}", reason);
    
    // 2. API hooks must have fired
    assert!(api_count > 0, "G1 FAILED: No API hooks fired");
    
    println!("=== G1 PASSED === ({} API calls, clean exit)", api_count);
}
