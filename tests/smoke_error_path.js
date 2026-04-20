// Smoke test: pass garbage data to emu.load() and confirm we get a proper
// JS exception (not a silent host crash). Before the fix, throwing deep in
// pe_loader would propagate C++ exception across the FFI and abort the process.

const { Emulator } = require('../hexcore-elixir.win32-x64-msvc.node');

const emu = new Emulator({ arch: 'x86_64', maxInstructions: 1000, verbose: false });

try {
    const garbage = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
    emu.load(garbage);
    console.error('FAILED: expected a JS exception from loading garbage');
    process.exit(1);
} catch (e) {
    console.log('OK — caught proper JS exception:', e.message);
}

try {
    // Massive allocation request should still be handled gracefully
    const huge = Buffer.alloc(8);
    huge.writeUInt16LE(0x5A4D, 0); // DOS_SIGNATURE  (invalid PE after that)
    emu.load(huge);
    console.error('FAILED: expected JS exception from truncated PE');
    process.exit(1);
} catch (e) {
    console.log('OK — caught proper JS exception (truncated PE):', e.message);
}

// After two failed loads, the emulator should still be usable
const fs = require('fs');
const path = require('path');
const data = fs.readFileSync(path.resolve(__dirname, 'fixtures', 'hello_msvc.exe'));
emu.load(data);
const reason = emu.run(emu.regRead(41) || 0n, 0n);
console.log('OK — after two error paths, run succeeded:', reason.kind, 'insns=' + reason.instructionsExecuted);
emu.dispose();
console.log('ALL SMOKE TESTS PASSED');
