// Reproduce the "two sequential Emulators in the same process" scenario.
// If this crashes on emu2, we have the same bug the Extension Host hits.

const path = require('path');
const fs = require('fs');

const { Emulator } = require(path.resolve(__dirname, '..', 'hexcore-elixir.win32-x64-msvc.node'));

const exe = path.resolve(__dirname, 'fixtures', 'hello_msvc.exe');
console.log('[repro] loading', exe);
const data = fs.readFileSync(exe);

function run(label) {
    console.log(`[repro] ${label}: constructing`);
    const emu = new Emulator({ arch: 'x86_64', maxInstructions: 100_000, verbose: false });
    console.log(`[repro] ${label}: loading`);
    const entry = emu.load(data);
    console.log(`[repro] ${label}: entry = 0x${entry.toString(16)}`);
    const rip = emu.regRead(41);
    const start = rip || entry;
    console.log(`[repro] ${label}: running from 0x${start.toString(16)}`);
    const reason = emu.run(start, 0n);
    console.log(`[repro] ${label}: stop = ${reason.kind} insns = ${reason.instructionsExecuted}`);
    emu.dispose();
    console.log(`[repro] ${label}: disposed`);
}

try {
    run('emu1');
    run('emu2');
    console.log('[repro] OK — two sequential emulations in same process succeeded');
} catch (e) {
    console.error('[repro] FAILED:', e);
    process.exit(1);
}
