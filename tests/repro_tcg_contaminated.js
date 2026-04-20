// Stronger contamination repro per follow-up diagnosis:
// Step 1 must actually run uc_emu_start and execute real instructions
// so libuc's TCG cache gets populated before our engine touches it.
//
// Before the /EHa + TB flush fix, this scenario can crash with SEH 0xC0000005
// inside our first uc_emu_start. After the fix, TB cache is flushed and the
// run succeeds — or if a crash still happens, the per-line fprintf trace
// identifies the exact failing step.

const path = require('path');
const fs = require('fs');

console.log('[step 1] loading hexcore_unicorn and running REAL emuStart to populate TCG cache');
const HC = require(path.resolve(__dirname, 'hexcore_unicorn.node'));

// Create an engine and run a non-trivial program so the TCG code generator
// actually produces translation blocks that live in the process-global cache.
const uc = new HC.Unicorn(HC.ARCH.X86, HC.MODE.MODE_64);

const base = 0x100000n;
uc.memMap(base, 0x2000, HC.PROT.ALL);

// Program: mov rax,1 ; mov rbx,2 ; mov rcx,3 ; add rax,rbx ; add rax,rcx ; nop ; nop ; nop ; ret
// MSVC x64 asm
const prog = Buffer.from([
    0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,  // mov rax, 1
    0x48, 0xc7, 0xc3, 0x02, 0x00, 0x00, 0x00,  // mov rbx, 2
    0x48, 0xc7, 0xc1, 0x03, 0x00, 0x00, 0x00,  // mov rcx, 3
    0x48, 0x01, 0xd8,                           // add rax, rbx
    0x48, 0x01, 0xc8,                           // add rax, rcx
    0x90, 0x90, 0x90,                           // nop*3
    0xf4,                                        // hlt  (clean halt so emuStart returns OK)
]);
uc.memWrite(base, prog);
uc.regWrite(HC.X86_REG.RSP, 0x100500n);

console.log('[step 1] emuStart — executes real code, populates TCG cache');
try {
    uc.emuStart(base, base + BigInt(prog.length), 0, 100);
    console.log('[step 1] emuStart returned cleanly, RAX =', uc.regRead(HC.X86_REG.RAX));
} catch (e) {
    console.log('[step 1] emuStart exception (continuing):', e.message);
}
uc.close();
console.log('[step 1] closed hexcore_unicorn engine — TCG cache now populated + potentially stale');

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
    console.log('[REPRO RESULT] OK — Elixir survived TCG-contaminated process');
} catch (e) {
    console.error('[REPRO RESULT] FAILED with JS exception:', e);
    process.exit(1);
}
