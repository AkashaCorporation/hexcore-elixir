// Simulate the Extension Host contaminated-process scenario.
// Step 1: Load the extension's hexcore_unicorn.node and run full emuStart cycle
//         (matches what hexcore-debugger does before our code runs).
// Step 2: Load our hexcore-elixir .node and run an emulation.
//
// Expected: crash (repro). If it succeeds, the fix has landed.

const path = require('path');
const fs = require('fs');

console.log('[step 1] pre-loading hexcore_unicorn.node to taint unicorn.dll state...');
const HC = require(path.resolve(__dirname, 'hexcore_unicorn.node'));

try {
    console.log('[step 1] creating Unicorn engine (uc_open) ...');
    const uc = new HC.Unicorn(HC.ARCH.X86, HC.MODE.MODE_64);
    console.log('[step 1] created');

    // Map some memory
    const base = 0x100000n;
    const size = 0x2000;
    uc.memMap(base, size, HC.PROT.ALL);

    // Write a tiny x64 program: mov rax, 0x42 ; ret
    // REX.W + mov rax, imm64 is 48 b8 42 00 00 00 00 00 00 00, then c3
    const code = Buffer.from([0x48, 0xb8, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3]);
    uc.memWrite(base, code);

    // Actually run it — this touches TCG code generation
    console.log('[step 1] emuStart...');
    try {
        uc.emuStart(base, base + BigInt(code.length), 0, 10);
    } catch (e) {
        console.log('[step 1] emuStart error (expected, CPU exception on ret):', e.message);
    }
    console.log('[step 1] emuStart done');

    uc.close();
    console.log('[step 1] closed hexcore_unicorn engine');
} catch (e) {
    console.log('[step 1] hexcore_unicorn setup exception (continuing):', e.message);
}

// Force GC if available, to drop lingering references
if (global.gc) global.gc();

console.log('');
console.log('[step 2] loading our hexcore-elixir .node...');
const { Emulator } = require(path.resolve(__dirname, '..', 'hexcore-elixir.win32-x64-msvc.node'));

const exe = path.resolve(__dirname, 'fixtures', 'Malware HexCore Defeat.exe');
console.log('[step 2] loading', exe);
const data = fs.readFileSync(exe);

try {
    console.log('[step 2] constructing Elixir Emulator');
    const emu = new Emulator({ arch: 'x86_64', maxInstructions: 100_000, verbose: false });
    console.log('[step 2] loading binary');
    const entry = emu.load(data);
    console.log('[step 2] entry = 0x' + entry.toString(16));
    console.log('[step 2] running...');
    const reason = emu.run(entry, 0n);
    console.log('[step 2] stop =', reason.kind, 'insns =', reason.instructionsExecuted);
    emu.dispose();
    console.log('[REPRO RESULT] OK — Elixir survived contaminated process');
} catch (e) {
    console.error('[REPRO RESULT] FAILED with JS exception:', e);
    process.exit(1);
}
