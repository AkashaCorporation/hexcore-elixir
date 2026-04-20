//! Parity Gate: api_log_snapshot() returns detailed per-call records,
//! not the legacy "api_log_count_N" summary stub.
//!
//! Regression guard for GET_API_CALLS_STUB_FIX (handoff 2026-04-17).
//! See handoff/GET_API_CALLS_STUB_FIX.md for background.

use elixir_core::emulator::{Emulator, EmulatorConfig};
use elixir_core::types::{Arch, OsType};

fn create_windows_emulator() -> Emulator {
    let config = EmulatorConfig {
        arch: Arch::X86_64,
        os: OsType::Windows,
        stack_size: 2 * 1024 * 1024,
        heap_size: 16 * 1024 * 1024,
        permissive_memory: true,
    };
    let mut emu = Emulator::new(config).expect("Failed to create emulator");
    emu.set_permissive_memory(true).expect("enable permissive memory");
    emu
}

#[test]
fn api_log_returns_detailed_entries() {
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/Malware HexCore Defeat.exe");

    if !fixture_path.exists() {
        eprintln!("SKIPPED: PE fixture not found at {:?}", fixture_path);
        return;
    }

    let pe_data = std::fs::read(&fixture_path).expect("read PE fixture");
    let mut emu = create_windows_emulator();
    let entry = emu.load(&pe_data).expect("load PE");
    let _ = emu.run(entry, 0, 500_000);

    let count = emu.api_log_count();
    let entries = emu
        .api_log_snapshot()
        .expect("api_log_snapshot should succeed on a loaded PE");

    assert_eq!(
        entries.len() as u64,
        count,
        "snapshot length must match api_log_count()"
    );

    // Regression guard: the legacy stub returned exactly one entry named
    // "api_log_count_<N>" with address 0. If this ever reappears, the
    // C++ engine is logging summaries instead of per-call records.
    assert!(
        entries.iter().all(|e| !e.name.starts_with("api_log_count_")),
        "found legacy stub 'api_log_count_*' — get_api_calls regressed"
    );

    if !entries.is_empty() {
        // The stub region lives in 0x70000000-0x70100000 per
        // api_hooks.cpp STUB_REGION_BEGIN/END. Every captured call must
        // have fired from there; a pc of 0 means the stub address was
        // not threaded through when the log entry was written.
        assert!(
            entries.iter().all(|e| e.pc_address >= 0x70000000 && e.pc_address < 0x70100000),
            "pc_address outside stub region — wire-up broken"
        );

        assert!(
            entries.iter().all(|e| !e.name.is_empty() && e.name != "unknown"),
            "found entries with missing/unknown names"
        );

        println!(
            "api_log_detail: {} calls, first = {}!{} pc=0x{:x} ret=0x{:x} args={}",
            entries.len(),
            entries[0].module,
            entries[0].name,
            entries[0].pc_address,
            entries[0].return_value,
            entries[0].arguments.len()
        );
    } else {
        println!("api_log_detail: zero calls captured (PE may have exited before any import fired)");
    }
}
