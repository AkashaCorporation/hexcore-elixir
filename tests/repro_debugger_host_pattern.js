// Matches what hexcore-debugger does in the VS Code Extension Host BEFORE
// migrating to its worker subprocess. Key detail: it never calls
// uc_emu_start in the host — only setup calls (uc_open, mem_map, mem_write,
// reg_write, uc_close). The worker subprocess is what actually executes.
//
// Region list from the Extension Host log provided by the user.
// If the crash is triggered by this specific libuc state-touch pattern
// (no TCG involvement), this is the repro.

const path = require('path');
const fs = require('fs');

const HC = require(path.resolve(__dirname, 'hexcore_unicorn.node'));

console.log('[step 1] simulating hexcore-debugger host-side setup (NO emuStart)');
const uc = new HC.Unicorn(HC.ARCH.X86, HC.MODE.MODE_64);

// Exact region list from the update log. Each tuple is [base, sizeInBytes, prot].
// Using HC.PROT.ALL for simplicity — the debugger uses RW or RX depending on
// region role but the state-touching on libuc's side is the same.
const regions = [
    [0x05000000n, 0x01000000, HC.PROT.ALL], // 16 MiB heap
    [0x70000000n, 0x00100000, HC.PROT.ALL], // 1 MiB stub region
    [0x71000000n, 0x00800000, HC.PROT.ALL], // 8 MiB data imports
    [0x7ffc0000n, 0x00010000, HC.PROT.ALL], // TLS vector
    [0x7ffd0000n, 0x00001000, HC.PROT.ALL], // PEB
    [0x7ffde000n, 0x00002000, HC.PROT.ALL], // TEB
    [0x7fff0000n, 0x00100000, HC.PROT.ALL], // stack
    [0x140000000n, 0x0000a000, HC.PROT.ALL], // image (MSVC preferred base)
];

for (const [base, size, prot] of regions) {
    try {
        uc.memMap(base, size, prot);
        console.log('[step 1] mem_map 0x' + base.toString(16) + ' size=0x' + size.toString(16));
    } catch (e) {
        console.log('[step 1] mem_map failed for 0x' + base.toString(16) + ':', e.message);
    }
}

// Write a few bytes to a couple of regions — matches debugger's header load.
uc.memWrite(0x140000000n, Buffer.from([0x4d, 0x5a])); // 'MZ'
uc.memWrite(0x7fff0000n, Buffer.alloc(8));

// Set RIP/RSP like debugger does
uc.regWrite(HC.X86_REG.RIP, 0x140002880n);
uc.regWrite(HC.X86_REG.RSP, 0x7fffff00n);

console.log('[step 1] closing engine WITHOUT running emuStart');
uc.close();
console.log('[step 1] closed — libuc has been touched but TCG never populated');

console.log('');
console.log('[step 2] loading our hexcore-elixir .node...');
const { Emulator } = require(path.resolve(__dirname, '..', 'hexcore-elixir.win32-x64-msvc.node'));

const exe = path.resolve(__dirname, 'fixtures', 'Malware HexCore Defeat.exe');
const data = fs.readFileSync(exe);

try {
    console.log('[step 2] new Emulator');
    const emu = new Emulator({ arch: 'x86_64', maxInstructions: 1_000_000, verbose: false });
    console.log('[step 2] load');
    const entry = emu.load(data);
    console.log('[step 2] entry = 0x' + entry.toString(16));
    console.log('[step 2] run');
    const reason = emu.run(entry, 0n);
    console.log('[step 2] stop =', reason.kind, 'insns =', reason.instructionsExecuted);
    console.log('[step 2] api_call_count =', emu.getApiCallCount());
    emu.dispose();
    console.log('[REPRO RESULT] OK — Elixir survived debugger host pattern');
} catch (e) {
    console.error('[REPRO RESULT] FAILED with JS exception:', e);
    process.exit(1);
}
