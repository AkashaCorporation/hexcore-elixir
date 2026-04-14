//! Parity Gate G3: Ashaka Shadow v3 — ≥20,000 API calls, zero crashes

use elixir_core::emulator::{Emulator, EmulatorConfig};
use elixir_core::types::{Arch, OsType, SimpleStopReason};

#[test]
fn parity_gate_g3_ashaka_shadow_api_coverage() {
    let binary = std::fs::read("../../tests/fixtures/Malware HexCore Defeat.exe")
        .expect("Failed to read test fixture");
    
    let config = EmulatorConfig {
        arch: Arch::X86_64,
        os: OsType::Windows,
        stack_size: 2 * 1024 * 1024,
        heap_size: 16 * 1024 * 1024,
        permissive_memory: true,
    };
    let mut emu = Emulator::new(config).expect("Failed to create emulator");
    emu.set_permissive_memory(true).expect("Failed to set permissive memory");
    
    let entry = emu.load(&binary).expect("Failed to load PE binary");
    println!("G3: Entry point = 0x{:x}", entry);
    
    // Run with 1M instruction limit (matching ground truth)
    let result = emu.run(entry, 0, 1_000_000);
    println!("G3: run() returned {:?}", result);
    
    let reason = emu.stop_reason();
    println!("G3: Stop reason = {:?}", reason);
    
    let api_count = emu.api_log_count();
    println!("G3: {} API calls captured (target: ≥20,000, ground truth: 23,128)", api_count);
    
    // For debugging: print the instruction count if available
    // and check RIP to see where we stopped
    if let Ok(rip) = emu.reg_read(28) {  // UC_X86_REG_RIP = 28
        println!("G3: RIP at stop = 0x{:x}", rip);
    }
    
    // G3 criteria: must not crash
    assert!(reason == SimpleStopReason::Exit || reason == SimpleStopReason::InsnLimit,
        "G3 FAILED: Unexpected stop reason {:?}", reason);
    
    // G3 criteria: ≥20,000 API calls
    assert!(api_count >= 20_000,
        "G3 FAILED: Only {} API calls (need ≥20,000)", api_count);
    
    // Check within 5% of ground truth (23,128)
    let ground_truth = 23_128u64;
    let diff_pct = ((api_count as f64 - ground_truth as f64).abs() / ground_truth as f64) * 100.0;
    println!("G3: Diff from ground truth: {:.1}% ({} vs {})", diff_pct, api_count, ground_truth);
    
    assert!(diff_pct <= 5.0,
        "G3 FAILED: API count diff {:.1}% exceeds 5% threshold", diff_pct);
    
    println!("=== G3 PASSED === ({} API calls, {:.1}% diff from ground truth)", api_count, diff_pct);
}
