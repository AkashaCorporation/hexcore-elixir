// Smoke test for getApiCalls() NAPI surface — validates that the
// Rust/C++ fix for GET_API_CALLS_STUB_FIX reaches Node and produces
// detailed per-call records (name, module, address, returnValue,
// arguments[]) rather than the legacy "api_log_count_N" summary stub.

const fs = require('fs');
const path = require('path');
const { Emulator } = require('../crates/hexcore-elixir');

const fixture = path.join(__dirname, 'fixtures', 'Malware HexCore Defeat.exe');
if (!fs.existsSync(fixture)) {
    console.error('SKIP: fixture missing at', fixture);
    process.exit(0);
}

const emu = new Emulator({
    arch: 'x86_64',
    os: 'windows',
    maxInstructions: 500_000,
    permissiveMemory: true,
});

const entry = emu.load(fs.readFileSync(fixture));
console.log('entry =', entry.toString(16));

const result = emu.run(entry, 0n);
console.log('stop:', result.kind, 'insns:', result.instructionsExecuted);

const count = emu.getApiCallCount();
const calls = emu.getApiCalls();
console.log('count:', count, 'calls.length:', calls.length);

if (calls.length !== count) {
    console.error('FAIL: length mismatch');
    process.exit(1);
}

if (calls.some((c) => c.name.startsWith('api_log_count_'))) {
    console.error('FAIL: legacy stub "api_log_count_*" still present');
    process.exit(1);
}

if (calls.length > 0) {
    const first = calls[0];
    console.log('first call:', {
        name: first.name,
        module: first.module,
        address: '0x' + first.address.toString(16),
        returnValue: '0x' + first.returnValue.toString(16),
        argCount: first.arguments.length,
        args: first.arguments.map((a) => '0x' + a.toString(16)),
    });

    for (const c of calls) {
        if (!c.name || c.name === 'unknown') {
            console.error('FAIL: call with empty/unknown name', c);
            process.exit(1);
        }
        if (c.address < 0x70000000n || c.address >= 0x70100000n) {
            console.error('FAIL: pc outside stub region', c.address.toString(16));
            process.exit(1);
        }
        if (!Array.isArray(c.arguments)) {
            console.error('FAIL: arguments not an array', c);
            process.exit(1);
        }
    }
    console.log('PASS:', calls.length, 'detailed entries verified');
} else {
    console.log('PASS: zero calls (nothing to verify)');
}

emu.dispose();
