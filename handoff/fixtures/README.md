# Test Fixtures

This directory holds the **Parity Gate test binaries** and their **ground-truth execution traces** from the HexCore reference implementation. The swarm uses these to verify that Elixir reproduces the reference behavior.

## What you need to populate (user action required)

The monorepo maintainer (you, reading this) must manually place the following files into this directory before handing the package to the swarm. I did not copy them automatically because they're executable binaries (even though they're inoffensive test samples) and that kind of file transfer should be a conscious decision by you, not an automated one.

```
handoff/fixtures/
├── README.md                                  ← this file
├── binaries/
│   ├── malware-hexcore-defeat-v1.exe          ← source: AkashaCorporationMalware/.../x64/Release/Malware HexCore Defeat.exe (v1 build)
│   ├── malware-hexcore-defeat-v2.exe          ← v2 "Ashaka" build
│   ├── malware-hexcore-defeat-v3.exe          ← v3 "Ashaka Shadow" build (the one tested on 2026-04-14)
│   ├── hello-world-msvc-x64.exe               ← minimal MSVC Hello World, compile with `cl /EHsc hello.cpp`
│   └── mali_kbase.ko                          ← optional: Linux kernel module from the 3.7.4 test corpus
└── ground-truth-traces/
    ├── v3-hexcore-debugger.json               ← the 23,128 API calls from the 2026-04-14 successful run
    ├── v1-hexcore-debugger.json               ← similar, from a v1 run (generate separately)
    ├── v2-hexcore-debugger.json               ← similar, from a v2 run
    └── hello-world-hexcore-debugger.json      ← similar, from Hello World
```

## How to populate `binaries/`

```bash
# From vscode-main root:
mkdir -p /c/Users/Mazum/Desktop/HexCore-Elixir/handoff/fixtures/binaries
cp "/c/Users/Mazum/Desktop/AkashaCorporationMalware/Malware HexCore Defeat/x64/Release/Malware HexCore Defeat.exe" \
   /c/Users/Mazum/Desktop/HexCore-Elixir/handoff/fixtures/binaries/malware-hexcore-defeat-v3.exe

# For v1 and v2 you need their own build output directories (different repos/branches)
# If you don't have them readily available, handing only v3 is ALSO acceptable — the gate on v3 is strictly harder than v1/v2, so passing G3 implies passing G1/G2 in practice.

# Hello World — compile from a minimal source
cat > /tmp/hello.cpp << 'EOF'
#include <cstdio>
int main(int argc, char** argv) {
    printf("argc=%d\n", argc);
    return 0;
}
EOF
# Compile with MSVC's cl.exe into handoff/fixtures/binaries/hello-world-msvc-x64.exe

# mali_kbase.ko — optional, for G5 (Linux ELF .ko gate)
cp /path/to/your/mali_kbase.ko \
   /c/Users/Mazum/Desktop/HexCore-Elixir/handoff/fixtures/binaries/
```

## How to populate `ground-truth-traces/`

The reference implementation already generated these traces. They live at:

```
C:\Users\Mazum\Desktop\AkashaCorporationMalware\Malware HexCore Defeat\hexcore-reports\18-emulation-result.json
```

That file is the 2026-04-14 successful run (23,128 API calls, 1M instructions, no crash). Copy it as:

```bash
cp "/c/Users/Mazum/Desktop/AkashaCorporationMalware/Malware HexCore Defeat/hexcore-reports/18-emulation-result.json" \
   /c/Users/Mazum/Desktop/HexCore-Elixir/handoff/fixtures/ground-truth-traces/v3-hexcore-debugger.json
```

For v1, v2, and Hello World traces, run the reference implementation against those binaries and save the resulting `18-emulation-result.json` files under different names. This can be done in one batch — fire `hexcore.debugger.emulateFullHeadless` from the VS Code command palette on each binary in turn, then rename the outputs.

## What the ground-truth trace contains

The JSON structure is:

```json
{
  "file": "...path...",
  "architecture": "x64",
  "executionBackend": "hexcore-unicorn",
  "fileType": "PE",
  "crashed": false,
  "error": null,
  "state": {
    "isRunning": true,
    "isPaused": true,
    "currentAddress": "0x140001cb0",
    "instructionsExecuted": 1000000
  },
  "registers": { "rax": "0x...", "rbx": "0x...", ... },
  "apiCalls": [
    { "dll": "kernel32.dll", "name": "GetCurrentThreadId", "returnValue": "0x1004", "arguments": [...], "pcAddress": "0x..." },
    ...
  ],
  "stdout": "",
  "memoryRegions": [ ... ]
}
```

**Key fields the swarm's Parity Gate checks**:

- `crashed`: must be `false`
- `apiCalls` length: must be within 5% of ground truth for v3 (target ~23,128)
- Unique API names in `apiCalls`: must be a superset of the required set `{GetSystemTimeAsFileTime, GetCurrentThreadId, GetCurrentProcessId, QueryPerformanceCounter, _initterm_e, _initterm, _get_initial_narrow_environment, __p___argv, __p___argc, Sleep, RegOpenKeyA, GetComputerNameA}`
- `stdout`: optional — if the swarm implements WriteFile → stdout capture, this should contain Hello World's `argc=1\n` output
- For Hello World: `instructionsExecuted` must be < 100,000 (must NOT hit the 1M cap)

## Running Elixir against the gate

Once the swarm has `elixir-cli` working (Phase 1.5), the gate check is:

```bash
# Build Elixir
cmake -B engine/build -S engine -DCMAKE_BUILD_TYPE=Release
cmake --build engine/build --config Release
cargo build --release -p elixir-core

# Run gate tests
./engine/build/tools/elixir_tool run \
    handoff/fixtures/binaries/malware-hexcore-defeat-v3.exe \
    --arch x86_64 --os windows \
    --max-insns 1000000 \
    --output /tmp/elixir-v3-trace.json

# Diff against ground truth
python3 handoff/scripts/compare-traces.py \
    --ground-truth handoff/fixtures/ground-truth-traces/v3-hexcore-debugger.json \
    --candidate /tmp/elixir-v3-trace.json \
    --tolerance 5%
```

The `compare-traces.py` script (swarm writes this in Phase 5 prep — not yet created) should:
1. Parse both JSON files
2. Compare `apiCalls` lengths within `--tolerance` (default 5%)
3. Assert the unique API name set is a superset of the required set
4. Assert `crashed: false` in the candidate
5. Exit 0 on pass, non-zero on fail

## Binaries are inoffensive — but still treat with care

All the test binaries are **benign**. The "Malware HexCore Defeat" series is research code from AkashaCorporation designed to stress-test emulators; it opens a GitHub URL and reads system info, nothing else. The source is in `Malware HexCore Defeat.cpp` in the AkashaCorporationMalware directory if the swarm wants to audit it.

Nonetheless:
- Do not rename them to look like real malware
- Do not upload them to shared CI systems without disclosing the content
- The swarm should run them only inside Elixir's emulator, never on the host OS
- Keep the `handoff/` directory out of public forks of the Elixir repo until the Parity Gate is passed and the binaries are no longer needed
