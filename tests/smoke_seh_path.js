// Exercise the SEH-guarded path with an invalid start address.
// uc_emu_start will fail internally (not with a real AV, but with
// UC_ERR_EXCEPTION) and return through the helper's uc_err result.
// This verifies the helper is wired into the call chain correctly.

const path = require('path');
const fs = require('fs');

const { Emulator } = require(path.resolve(__dirname, '..', 'hexcore-elixir.win32-x64-msvc.node'));

const emu = new Emulator({ arch: 'x86_64', maxInstructions: 1000, verbose: false });

// Load a real binary so we have mapped regions, then run from an address
// that isn't mapped. uc_emu_start will return an error (not crash).
const data = fs.readFileSync(path.resolve(__dirname, 'fixtures', 'hello_msvc.exe'));
emu.load(data);

// Run from an unmapped address — Unicorn should return UC_ERR_EXCEPTION
// or similar, NOT fault the process. Exercise the SEH helper path.
const reason = emu.run(0xdeadbeefn, 0n);
console.log('SEH-guarded run returned reason =', reason.kind, 'message =', reason.message);

// Emulator should still be usable for regular reads — tainted flag only
// activates on real SEH faults, not on clean uc_err_to_elixir conversion.
console.log('api_call_count =', emu.getApiCallCount());
emu.dispose();
console.log('OK — SEH wrapper path exercised, engine survived');
