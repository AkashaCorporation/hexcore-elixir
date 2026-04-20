// Heavier contamination attempt: do many uc_open/mem_map/emu_start/uc_close cycles
// to really stress TCG / internal state before handing off.

const path = require('path');
const fs = require('fs');

const HC = require(path.resolve(__dirname, 'hexcore_unicorn.node'));

function taint_round(i) {
    const uc = new HC.Unicorn(HC.ARCH.X86, HC.MODE.MODE_64);
    const base = 0x100000n + BigInt(i * 0x10000);
    const size = 0x2000;
    try { uc.memMap(base, size, HC.PROT.ALL); } catch(e) {}

    // Larger program mix so TCG generates multiple blocks
    // inc rax; inc rbx; inc rcx; dec rdx; jmp .; hlt
    const code = Buffer.from([
        0x48, 0xff, 0xc0,       // inc rax
        0x48, 0xff, 0xc3,       // inc rbx
        0x48, 0xff, 0xc1,       // inc rcx
        0x48, 0xff, 0xca,       // dec rdx
        0xeb, 0xfe,             // jmp $  (infinite loop, stopped by count)
        0xf4,                   // hlt
    ]);
    try { uc.memWrite(base, code); } catch(e) {}
    try { uc.emuStart(base, base + BigInt(code.length), 0, 1000); } catch(e) {}
    try { uc.close(); } catch(e) {}
}

console.log('[step 1] running 20 taint rounds...');
for (let i = 0; i < 20; i++) {
    taint_round(i);
}
console.log('[step 1] done tainting');

// Keep at least one hexcore-unicorn engine OPEN to hold unicorn.dll in a "dirty" state
console.log('[step 1b] opening a leftover engine to keep unicorn.dll dirty');
const leftover = new HC.Unicorn(HC.ARCH.X86, HC.MODE.MODE_64);
leftover.memMap(0x200000n, 0x2000, HC.PROT.ALL);
leftover.memWrite(0x200000n, Buffer.from([0x48, 0xff, 0xc0, 0xeb, 0xfe]));
try { leftover.emuStart(0x200000n, 0x200005n, 0, 100); } catch(e) {}
// DO NOT close — keep it alive while we use our engine

console.log('');
console.log('[step 2] loading our hexcore-elixir .node...');
const { Emulator } = require(path.resolve(__dirname, '..', 'hexcore-elixir.win32-x64-msvc.node'));

const exe = path.resolve(__dirname, 'fixtures', 'Malware HexCore Defeat.exe');
const data = fs.readFileSync(exe);

try {
    console.log('[step 2] constructing Elixir Emulator');
    const emu = new Emulator({ arch: 'x86_64', maxInstructions: 1_000_000, verbose: false });
    console.log('[step 2] loading binary');
    const entry = emu.load(data);
    console.log('[step 2] entry = 0x' + entry.toString(16));
    console.log('[step 2] running...');
    const reason = emu.run(entry, 0n);
    console.log('[step 2] stop =', reason.kind, 'insns =', reason.instructionsExecuted);
    console.log('[step 2] api_call_count =', emu.getApiCallCount());
    emu.dispose();
    console.log('[REPRO RESULT] OK — Elixir survived heavily contaminated process');
} catch (e) {
    console.error('[REPRO RESULT] FAILED with JS exception:', e);
    process.exit(1);
} finally {
    try { leftover.close(); } catch(e) {}
}
