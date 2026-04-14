// HexCore Elixir — Phase 2 Loader Tests
//
// Validates binary loading: format detection, PE/ELF loaders, error handling.
//
// Apache-2.0 licensed. No code copied verbatim.

use elixir_core::emulator::{Emulator, EmulatorConfig};
use elixir_core::types::{Arch, OsType};

#[test]
fn test_load_unknown_format_fails() {
    let config = EmulatorConfig {
        arch: Arch::X86_64,
        os: OsType::Bare,
        stack_size: 0x1000,
        heap_size: 0,
        permissive_memory: false,
    };
    let mut emu = Emulator::new(config).expect("Failed to create emulator");
    
    // Random bytes - not a valid PE or ELF
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
    let result = emu.load(&garbage);
    assert!(result.is_err(), "Loading unknown format should fail");
}

#[test]
fn test_load_pe_fixture() {
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/Malware HexCore Defeat.exe");
    
    if !fixture_path.exists() {
        eprintln!("SKIPPED: PE fixture not found at {:?}", fixture_path);
        return; // Skip gracefully if fixture not present
    }
    
    let data = std::fs::read(&fixture_path).expect("Failed to read PE fixture");
    
    let config = EmulatorConfig {
        arch: Arch::X86_64,
        os: OsType::Windows,
        stack_size: 0x100000,  // 1 MB
        heap_size: 0x1000000,  // 16 MB
        permissive_memory: true,
    };
    let mut emu = Emulator::new(config).expect("Failed to create emulator");
    emu.set_permissive_memory(true).expect("Enable permissive");
    
    let entry_point = emu.load(&data).expect("Failed to load PE");
    assert!(entry_point > 0, "Entry point should be non-zero");
    
    eprintln!("PE loaded successfully! Entry point: 0x{:x}", entry_point);
    
    // Try running a few instructions (may crash without full OS support, that's OK)
    // Just verify loading didn't crash
}

#[test]
fn test_minimal_pe_header_validation() {
    let config = EmulatorConfig {
        arch: Arch::X86_64,
        os: OsType::Windows,
        stack_size: 0x1000,
        heap_size: 0,
        permissive_memory: false,
    };
    let mut emu = Emulator::new(config).expect("Failed to create emulator");
    
    // Minimal DOS header with MZ magic but invalid PE — should fail gracefully
    let mut fake_pe = vec![0u8; 256];
    fake_pe[0] = 0x4D; // M
    fake_pe[1] = 0x5A; // Z
    // e_lfanew at offset 0x3C pointing to offset 0x80
    fake_pe[0x3C] = 0x80;
    // But no valid PE signature at 0x80 — should fail
    
    let result = emu.load(&fake_pe);
    assert!(result.is_err(), "Invalid PE should fail to load");
}
