# HexCore Elixir — Swarm Handoff Package

This directory is the **complete specification package** for the swarm implementing Phases 1–4 of HexCore Elixir. Everything here was extracted from the HexCore monorepo's reference implementation (`extensions/hexcore-debugger/`, `extensions/hexcore-unicorn/`, `extensions/hexcore-common/`) on **2026-04-14**, after the reference implementation successfully emulated `Malware HexCore Defeat.exe` v3 "Ashaka Shadow" end-to-end (1,000,000 instructions, 23,128 API calls, zero drops, zero crashes).

## Directory map

```
handoff/
├── README.md                           ← you are here
├── specs/                              ← authoritative behavior specs
│   ├── CLEAN_ROOM.md                   ← license policy — READ FIRST
│   ├── msvc-crt-stub-contract.md       ← the 6 CRT stubs + exit family
│   ├── data-import-detection.md        ← isDataImport + 4KB self-ref block
│   ├── peb-ldr-data-layout.md          ← TEB / PEB / PEB_LDR_DATA with empty lists
│   ├── win32-api-hooks.md              ← the 35 critical Win32 API handlers
│   └── sab-ring-buffer-layout.md       ← zero-copy ring buffer for Stalker
└── fixtures/                           ← test binaries + ground-truth traces
    └── README.md                       ← how to populate (needs user action)
```

## Reading order for a new swarm member

1. **`CLEAN_ROOM.md`** — license policy. Read this before opening any other file.
2. **`../../roadmap.md`** — the overall Elixir roadmap with phases, priorities, and the Parity Gate definition.
3. **`win32-api-hooks.md`** — get a sense of the API surface you'll need to stub.
4. **`msvc-crt-stub-contract.md`** — the CRT init sequence is the first thing the malware hits after entry.
5. **`data-import-detection.md`** — the C++ data import fix. Critical and non-obvious.
6. **`peb-ldr-data-layout.md`** — TEB/PEB setup. Also critical and non-obvious.
7. **`sab-ring-buffer-layout.md`** — only needed for Phase 4 (Stalker). Skip until Phase 1–3 are done.

## Reading order for specific phases

### Phase 1 — Core Engine

- `../../deps/hexcore-unicorn/include/unicorn/unicorn.h` — Unicorn 2.0.1 C API
- `../../deps/hexcore-unicorn/src/unicorn_wrapper.cpp` — reference NAPI wrapper (read for architecture, not copy)
- `../../deps/hexcore-unicorn/test/test.js` — the 29 reference tests you should port to Rust/C++

### Phase 2 — Loaders

- `data-import-detection.md` — PE loader's data import handling
- `peb-ldr-data-layout.md` — TEB/PEB memory constants
- Microsoft PE specification (docs.microsoft.com) — upstream reference
- ELF specification (`man 5 elf`) — for the Linux path

### Phase 3 — OS Emulation

- `msvc-crt-stub-contract.md` — CRT init sequence, CRT data block layout
- `win32-api-hooks.md` — the 35 critical handlers
- MSDN documentation per API — for behavior details not captured in the spec
- `peb-ldr-data-layout.md` — finalize the TEB/PEB integration

### Phase 4 — Instrumentation

- `sab-ring-buffer-layout.md` — binary layout for Stalker events
- `../../deps/hexcore-unicorn/src/unicorn_wrapper.cpp` — grep for `CodeHookSabCB` and `hookAddSAB` for the existing SAB hook pattern (read only, do not copy)
- `../../deps/hexcore-unicorn/test/test_sab_hook.js` — reference SAB hook tests
- `../../deps/hexcore-unicorn/test/test_sab_benchmark.js` — throughput benchmark target

## How to use this package

1. **Read `CLEAN_ROOM.md` first.** It defines what you can and cannot copy.
2. **Read the roadmap at `../roadmap.md`.** That's the phased plan with dependencies, effort estimates, and the Parity Gate (G1–G5) that defines "done".
3. **Start Phase 1.1** — wire Unicorn into `engine/src/core/engine.cpp`. Appendix B of the roadmap has the concrete first 6 steps.
4. **When a phase is complete, re-read the spec.** Did you miss anything? Specs are concise on purpose — every bullet is load-bearing.
5. **Use the fixtures directory for gate validation.** The Parity Gate requires running actual malware binaries; see `fixtures/README.md` for what to populate and where.

## What's NOT in this package

- **No copy-paste-ready code.** Every spec describes behavior and constraints, not implementation. The clean-room policy requires you to derive implementation from the spec.
- **No partial source from `hexcore-debugger/`.** The TypeScript reference is intentionally excluded from this handoff to prevent accidental verbatim copying. If you need to consult it during development, do so against a clone of the vscode-main monorepo — but declare the consultation in your PR's `LICENSE_AUDIT:` line.
- **No pre-built `.lib` files for Elixir itself.** Elixir builds its own engine from scratch using the vendored Unicorn headers/libs. There is no "start from here" shortcut.

## When to hand back

The handoff is complete when **all five Parity Gate tests pass**:

| # | Gate | How to verify |
|---|---|---|
| G1 | v1 malware completes | `elixir-cli run tests/fixtures/malware-hexcore-defeat-v1.exe` — emulator stops cleanly via `exit()`, no UC_ERR_* |
| G2 | v2 malware "Ashaka" completes with XOR decode observable | Same, plus dump memory at the decoded-string address after N instructions and verify the plaintext appears |
| G3 | v3 "Ashaka Shadow" reproduces ≥20k API calls + the required set | Run under elixir-cli, dump the apiCalls trace, grep for `RegOpenKeyA`, `GetComputerNameA`, `QueryPerformanceCounter`, `Sleep` (≥100 times). Compare count against `fixtures/ground-truth-traces/v3-hexcore-debugger.json` within 5% deviation |
| G4 | Clean MSVC Hello World completes via `exit()` | Doesn't hit the 1M instruction cap; apiCall trace includes `exit` at position < 100 |
| G5 | `mali_kbase.ko` loads and runs `kbase_jit_allocate` | Function executes, returns, no `UC_ERR_*`, instructions > 0 |

**Do not hand back a partial implementation.** A swarm that delivers "Phases 1–3 done, Phase 4 partial" creates integration debt: the monorepo maintainer has to either finish Phase 4 themselves (losing the time savings of delegation) or ship an incomplete Elixir (which fails G3 on the live malware corpus and blocks the 3.8.0 release).

If the swarm runs out of time or hits a blocker, the correct behavior is:
1. Finish the current phase to a testable checkpoint
2. Document the blocker in a `BLOCKERS.md` at the root of the Elixir repo
3. Preserve the partial implementation on a branch so it's not lost
4. Hand back WITHOUT claiming completion

## Who reviews the handback

When Elixir is returned, the HexCore monorepo maintainer will:
1. Run the Parity Gate tests against their own malware corpus (not the fixtures — the real binaries)
2. Run a clean-room audit on `engine/src/`, `crates/elixir-core/src/`, and `agents/src/` against `hexcore-debugger/src/` and `hexcore-unicorn/src/` — any suspicious similarity triggers a re-derivation
3. Build `extensions/hexcore-elixir/` in the monorepo (Phase 5, which the swarm is NOT responsible for)
4. Integrate into the hexcore-pipeline command registry
5. Ship as part of HexCore 3.8.0 stable or later

The swarm's responsibility ends at handback. Phase 5 (VS Code integration) is faster for the monorepo maintainer to do than to specify.

## Questions / clarifications

If the swarm encounters a gap in the specs — a behavior that's not documented but is needed for gate passage — the correct response is:

1. **Do not guess.** A wrong guess will pass the immediate test but fail on the real malware corpus.
2. **Do not open `hexcore-debugger/` TypeScript to reverse-engineer the behavior.** That breaks clean-room.
3. **File a `SPEC_GAP.md` entry** at the root of the Elixir repo describing: what behavior is missing, which gate needs it, what the swarm would guess.
4. **Ping the monorepo maintainer** for an authoritative answer to incorporate into the spec.

This handoff was written by the monorepo maintainer directly from the reference implementation, so gaps should be rare — but when they happen, the maintainer is the source of truth.

---

**Ready to start?** Open `../roadmap.md` → Appendix B (the 6 concrete Phase 1.1 steps). First call to `uc_open` in Elixir lives about 4 hours away.
