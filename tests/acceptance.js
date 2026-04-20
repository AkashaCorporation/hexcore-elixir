// Acceptance test — verbatim from the fix request.
const { Emulator } = require('../hexcore-elixir.win32-x64-msvc.node');
const fs = require('fs');
const path = require('path');

const exePath = path.resolve(__dirname, 'fixtures', 'hello_msvc.exe');

// First emulation — should work (already does today)
const emu1 = new Emulator({ arch: 'x86_64', maxInstructions: 100_000, verbose: false });
const data = fs.readFileSync(exePath);
emu1.load(data);
emu1.run(emu1.regRead(41) || 0n, 0n);
emu1.dispose();

// Second emulation in the SAME process — must NOT crash
const emu2 = new Emulator({ arch: 'x86_64', maxInstructions: 100_000, verbose: false });
emu2.load(data);
emu2.run(emu2.regRead(41) || 0n, 0n);
emu2.dispose();

console.log('OK — two sequential emulations in same process succeeded');
