# HexCore Elixir — Roadmap

> **Project Codename:** 🜇 **Project Azoth**
> **Public Name:** HexCore Elixir
> **Purpose:** Clean-room, Apache-2.0, cross-platform dynamic analysis framework — a licensed and architecturally modern successor to Qiling, with Frida-style instrumentation at the emulation layer.
> **Status (2026-04-14):** 🧪 Skeleton — 273 LOC of stubs across 4 tiers. No functional emulation yet.
> **Target release:** **HexCore 3.8.0 stable** — shipped as a thin wrapper extension that downloads the standalone `.node` at install time, same pattern as HexCore-Helix.

## Why "Azoth"?

In alchemy, **Azoth** is the esoteric name for mercury — the "animating spirit" that transforms matter. HexCore Elixir transforms static bytes into observable dynamic behavior; the codename captures the goal. Paracelsus called Azoth "the universal principle of transformation," which is literally what a dynamic analysis framework does.

This codename continues the HexCore hidden-arts theming started by **Project Perseus** (the SAB zero-copy IPC pipeline that shipped in Wave 2 — Perseus being the Greek hero who "slew" slow TSFN dispatch).

## Delivery shape

HexCore Elixir ships in the same shape as **HexCore-Helix**:

- **Standalone repo** (this one, `HexCore-Elixir/`) — where ALL engine/crates/agents code lives, including the NAPI-RS `.node` build. Published as GitHub Releases with prebuilt binaries via a CI matrix.
- **Thin wrapper extension** `extensions/hexcore-elixir/` inside the HexCore monorepo (`vscode-main`) — ~300-500 lines of TypeScript. Downloads the standalone `.node` at `postinstall` time via the same `hexcore-native-install.js` script pattern Helix uses. Registers VS Code commands, hosts the emulation panel UI.

**The HexCore monorepo never contains a vendor dump of Elixir.** No Rust source, no C++ source, no `deps/`. Only the TypeScript wrapper + a downloaded `.node`. This is identical to how Helix avoids polluting the main fork with LLVM/MLIR deps.

---

## Strategic Context

HexCore already has a working dynamic analysis path inside the main VS Code fork: `extensions/hexcore-debugger/` drives `hexcore-unicorn` via TypeScript, with a PE loader, TEB/PEB setup, ~35 Win32 API hooks, CRT init stubs, data-import handling, and a memory manager. On 2026-04-14 it successfully emulated `Malware HexCore Defeat.exe` v3 "Ashaka Shadow" end-to-end — **1,000,000 instructions, 23,128 API calls, anti-debug + anti-VM + timing checks observed, zero crashes**.

Elixir is being built alongside (not replacing) this path for reasons that hexcore-debugger cannot address within its architectural shape:

| Driver | hexcore-debugger (TS) | Elixir (C++/Rust) | Why it matters |
|---|---|---|---|
| **License surface** | MIT (inherits VS Code fork) | **Apache-2.0 clean-room** | Commercial deployment, enterprise licensing, avoids any GPL ambiguity from Qiling-ish references |
| **Performance ceiling** | ~30k insns/s with hooks (SAB) | **10M+ insns/s native** (post-migration) | Fuzzing, long-running sandboxing, snapshot-heavy workloads |
| **Instrumentation depth** | API-stub interception only | **Full Interceptor + Stalker** at UC layer | Frida-parity without the GPL/LGPL envelope |
| **Cross-platform OS** | Windows PE well-covered; ELF via disassembler | **PE / ELF / Mach-O** with VFS + Registry + POSIX syscalls | Linux kernel modules (mali_kbase.ko, kgsl), macOS binaries, cross-platform samples |
| **Snapshot / time-travel** | None | **First-class `elixir_snapshot_save/restore`** | Fuzzing determinism, bisection, crash root-cause |
| **Embedding** | VS Code extension only | Native static lib + NAPI crate + CLI | CI/CD pipelines, research tools outside the IDE |

The goal is **not** to rewrite hexcore-debugger in Rust. The goal is to build the foundation for capabilities hexcore-debugger structurally cannot deliver, while keeping hexcore-debugger as the stable production path until Elixir crosses the parity gate.

---

## Parity Gate (the single most important concept in this roadmap)

Elixir does not ship to the HexCore IDE until it passes **all five** of the following acceptance tests:

| # | Test | Ground truth reference |
|---|---|---|
| G1 | Emulate `Malware HexCore Defeat.exe` **v1** through `ExitProcess` without crash | hexcore-debugger reference run (2026-04-14) |
| G2 | Emulate v2 "Ashaka" with multi-byte XOR decode observable in memory | hexcore-debugger reference run |
| G3 | Emulate v3 "Ashaka Shadow": reach the anti-debug, anti-VM, timing, and djb2 hash resolver paths. Expect **≥ 20,000 API calls captured, zero drops**, and the full set `{RegOpenKeyA, GetComputerNameA, QueryPerformanceCounter, Sleep ≥ 100×}` in the trace | Hexcore-debugger 2026-04-14: 23,128 API calls, 1M insn cap, those exact APIs observed |
| G4 | Clean MSVC "Hello World" reaches `main()` and `return 0` via `exit()`, emulation terminates cleanly (no 1M cap) | Hexcore-debugger + Phase F+++ exit family stubs |
| G5 | `mali_kbase.ko` (ELF x86_64 kernel module) loads and executes `kbase_jit_allocate` without fault | Battle-tested in 3.7.4 via hexcore-debugger's ELF path |

**When G1–G5 pass: Elixir becomes the primary emulation path in a new VS Code extension (`extensions/hexcore-elixir/`) and hexcore-debugger is frozen to maintenance mode.** Until then, Elixir stays in its own repo and is exercised via its CLI and Rust integration tests only.

This gate is measurable, has ground-truth traces from today's run, and does not depend on subjective judgements about "feature complete". It also gives a clear escape hatch: if Elixir hits a structural wall before G5, we know before shipping it.

---

## Phase 1 — Core Engine (v0.1.x) — ~3 weeks

**Goal:** `elixir_run()` actually executes instructions. Upstream Unicorn wired in. Memory manager functional. Rust + NAPI bridges return real data.

### Files touched

- `engine/src/core/engine.cpp` — currently 99 lines of stubs returning `ELIXIR_ERR_*`. Target: ~400 lines with `uc_open`, `uc_mem_map`, `uc_emu_start`, `uc_reg_read/write`, plus a fault hook that auto-maps on demand (copy the battle-tested pattern from `extensions/hexcore-unicorn/src/unicorn_wrapper.cpp:1454` — the `InvalidMemHookCB` with the `< 0x1000` guard relaxed to be configurable).
- `engine/src/core/memory.cpp` — currently stub. Target: heap bump allocator, page-level tracking, protection changes, snapshot data source. Port the allocator design from `extensions/hexcore-debugger/src/memoryManager.ts` — it already handles `heapAlloc(size, zero)`, free list, auto-map fallback.
- `engine/include/elixir/elixir.h` — already defines the C API surface. **No changes needed** unless tier 2/3/4 require new exports.
- `crates/elixir-core/src/emulator.rs` — currently stub (14 lines in `lib.rs`). Target: `Emulator::new()`, `Emulator::run()`, `Emulator::read_mem()`, etc. — idiomatic Rust wrappers over the FFI.
- `crates/hexcore-elixir/src/lib.rs` — NAPI-RS class exports. Target: `Emulator` class with async `run()` method following the pattern in `extensions/hexcore-unicorn/src/unicorn_wrapper.cpp` `EmuAsyncWorker`.
- `engine/CMakeLists.txt` — wire `hexcore-unicorn` via `find_package` or `add_subdirectory`. The native `.lib` is already prebuilt in the main repo; Elixir should link against it rather than building its own copy.
- `engine/tools/elixir-cli` — tiny driver that accepts `elixir run <binary> --arch x86_64 --os windows` and prints the API call trace.

### Dependencies / what to reuse

- **DO reuse**: `hexcore-unicorn` as a dependency (git submodule or Rust crate). Do not build a second Unicorn. Version lock: **1.2.3** (current) — bump via the monorepo workflow.
- **DO NOT reuse**: any code from the `hexcore-debugger` TypeScript implementation verbatim. The port is conceptual, not a line-by-line translation — this is where the clean-room discipline matters.
- **Read before coding**: `extensions/hexcore-debugger/src/memoryManager.ts` and `extensions/hexcore-debugger/src/peLoader.ts` are legal to read but writing equivalent Rust/C++ from scratch; do not copy comments or identifier names wholesale.

### Acceptance criteria (what "Phase 1 done" means)

- `cargo test -p elixir-core` — at least one integration test that creates an `Emulator`, maps a 4KB page with `mov rax, 0x41; ret` shellcode, runs it, and asserts `rax == 0x41`.
- `elixir-cli run tests/shellcode/x64_mov_ret.bin` produces an identical result from the command line.
- `extensions/hexcore-unicorn/test/test.js` style test adapted to Elixir: **29/29 pass** on the ported test suite.
- **No memory leaks**: `elixir_destroy` called after `elixir_create` leaves zero bytes in the heap tracker.

### Effort: ~3 weeks (solo), 1 week (paired with an experienced Rust+C++ dev)

---

## Phase 2 — Loaders (v0.2.x) — ~4 weeks

**Goal:** Bytes on disk → executable emulator state. PE64 first (because the malware corpus is PE), ELF64 second, Mach-O last.

### PE Loader (priority)

**Reference implementation** — `extensions/hexcore-debugger/src/peLoader.ts` is battle-tested. It handles:
- DOS/PE header parsing, section mapping with correct page alignment
- Import table parsing with `createStub()` for functions
- **NEW (2026-04-14)**: `isDataImport()` + `createDataImportBlock()` — distinguishes MSVC C++ data exports like `std::cout` from function imports. **Port this**.
- **NEW (2026-04-14)**: TEB + PEB + PEB_LDR_DATA setup with empty circular `LIST_ENTRY` heads so hand-rolled PEB walkers don't NULL-deref.
- Base relocation application (`IMAGE_DIRECTORY_ENTRY_BASERELOC`)
- TLS directory (`IMAGE_DIRECTORY_ENTRY_TLS`) static slot 0 setup

**Target files**:
- `engine/src/loader/pe_loader.cpp` — currently 17 lines of stub. Target: ~800 lines matching the TS reference.
- `engine/src/loader/format_detect.cpp` — magic byte sniffing (`MZ`, `\x7fELF`, `feedface`/`feedfacf`, `cafebabe`).

### ELF Loader

**Reference implementation** — `extensions/hexcore-disassembler/src/elfBtfLoader.ts` + engine's internal ELF parsing for the `.ko` path. Already handles:
- Program headers (LOAD segments with page alignment)
- `.symtab` STT_FUNC enumeration
- `.rela.text` external symbol resolution (ELF ET_REL / kernel modules)
- BTF type info parsing (pure TS, ~550 lines)

**Target**: port the static ELF64 loader first (ET_EXEC), then ET_DYN, then ET_REL (kernel modules) in that order of difficulty.

### Mach-O Loader — DEFER to v0.3

Initial support only for PIE x86_64 executables. No Mach-O code signing verification, no DYLD_SHARED_CACHE, no fat binaries. The corpus doesn't need it yet.

### Acceptance criteria

- Load `Malware HexCore Defeat.exe` (PE64) and dump: number of sections, entry RVA, image base, import count split by data-import vs function-import (expected: 74 function, 2 data).
- Load `mali_kbase.ko` (ELF64 ET_REL) and dump: function count (expected: 7,313), number of relocations applied.
- Load `/bin/ls` (ELF64 ET_DYN) and run 10,000 instructions without crash.

### Effort: ~4 weeks

---

## Phase 3 — OS Emulation (v0.3.x) — ~6 weeks

**Goal:** Syscall dispatch + API hooks + VFS + Registry. This is where Elixir starts matching hexcore-debugger's behavior on real binaries.

### Critical path — Windows (because of the malware corpus)

Port the following from `extensions/hexcore-debugger/src/winApiHooks.ts` (currently ~1,100 lines handling ~35 APIs):

#### Must-have (to pass G3 — the v3 malware test)
- `GetSystemTimeAsFileTime`, `GetCurrentThreadId`, `GetCurrentProcessId`, `QueryPerformanceCounter`, `GetTickCount`, `GetTickCount64`, `Sleep`
- **CRT init stubs** — the 6 handlers × 3 DLL aliases shipped in Phase F: `__p___argv`, `__p___argc`, `_initterm`, `_initterm_e`, `_get_initial_narrow_environment`, `_get_initial_wide_environment`. Plus the `ensureCrtDataAllocated()` 256-byte block with narrow+wide argv arrays.
- **CRT exit stubs** — `exit`, `_exit`, `_Exit`, `quick_exit`, `abort` across 3 DLL aliases, each calling the emulator's stop equivalent.
- `IsDebuggerPresent` (return 0), `CheckRemoteDebuggerPresent`
- `GetModuleHandleA/W` (return image base on NULL, stub handle otherwise)
- `LoadLibraryA/W`, `GetProcAddress`, `FreeLibrary`
- `VirtualAlloc/Free/Protect/Query`, `HeapAlloc/Free/Create`, `GetProcessHeap`
- `CreateFileA/W`, `ReadFile`, `WriteFile`, `CloseHandle` (routed through VFS)
- `RegOpenKeyA/W`, `RegQueryValueExA/W`, `RegCloseKey` (routed through fake Registry)
- `GetComputerNameA/W` — must return a **non-VM-looking hostname** (e.g., `DESKTOP-USER01`)
- `ExitProcess` — calls `elixir_stop`

#### Nice-to-have (improves fidelity on broader corpus)
- `ShellExecuteA/W`, `WinExec` — route through the fake shell handler
- `CreateProcessA/W`, `CreateRemoteThread` — return fake handles, log the attempt
- `RtlGetVersion` — return Windows 10.0.19041 to match hexcore-debugger
- `WideCharToMultiByte`, `MultiByteToWideChar`, `__stdio_common_vsprintf_s` — printf family

### Critical path — Linux

Port from hexcore-debugger's ELF path + standard Qiling-like syscall table:
- `read`, `write`, `open`, `close`, `mmap`, `mprotect`, `munmap`, `brk`
- `exit`, `exit_group`, `set_tid_address`
- `ioctl` — routed through fake driver handlers (for kernel module testing: `mali_kbase.ko` expects specific ioctl codes)
- `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn` — stub implementations
- `uname`, `getuid`, `getpid`, `gettid`

### VFS (`engine/src/vfs/vfs.cpp`)

Currently 15 lines stub. Target: ~500 lines with in-memory file tree, mount points, and read/write/seek semantics. Qiling has a reference design but **do not port its code** — write from scratch against the POSIX spec.

### Registry (`engine/src/os/windows/registry.cpp`)

Currently stub. Target: hierarchical key/value store with five predefined roots (HKLM/HKCU/HKCR/HKU/HKCC). Pre-populate with a set of "clean machine" values that the malware's anti-VM check will accept as a real computer. Use Wave 2's `REGISTRY_ANTI_VM_SUBSTRINGS` list as the **negative** template (don't put any of those strings in the fake registry).

### TEB/PEB setup

**Port directly the v3.8.0-nightly work from peLoader.ts**:
- TEB64 offset 0x30 (self), 0x40 (PID), 0x48 (TID), 0x58 (TLS vector), 0x60 (PEB)
- PEB64 offset 0x02 (BeingDebugged=0), 0x10 (ImageBase), **0x18 (PEB_LDR_DATA)**
- PEB_LDR_DATA at PEB+0x200: Length=0x58, Initialized=1, three empty self-referential LIST_ENTRY heads

This is the single most important piece that's not in any public reference. It was discovered today by tracing the malware crash.

### Acceptance criteria

- G3 passes: v3 malware emulation reaches ≥ 20,000 API calls with the required set
- G1, G2, G4 pass simultaneously
- `strace`-style output matches hexcore-debugger's `apiCalls` trace within 5% deviation on the same sample

### Effort: ~6 weeks

---

## Phase 4 — Instrumentation (v0.4.x) — ~5 weeks

**Goal:** Frida-parity instrumentation API. This is where Elixir differentiates from hexcore-debugger, not just matches it.

### Interceptor (`engine/src/instrument/interceptor.cpp`)

Port the concepts (not code) from `frida-gum/src/interceptor.c`. Primitives:
- `Interceptor.attach(address, callbacks)` — inline hook via `uc_hook_add(UC_HOOK_CODE, ...)` at the target address, fires `onEnter`/`onLeave` callbacks
- `Interceptor.replace(address, new_func_address)` — divert execution; Unicorn pattern: `uc_hook_add(UC_HOOK_CODE)` + `uc_reg_write(UC_X86_REG_RIP, new_func)` + skip original instruction
- `Interceptor.detachAll()` — clean removal
- Argument access: `args[0]` reads from calling-convention register/stack slot

### Stalker (`engine/src/instrument/stalker.cpp`)

Basic block tracing via `UC_HOOK_BLOCK`. Primitives:
- `Stalker.follow(thread, { events: ['call', 'ret', 'exec'] })` — emit events as execution flows through basic blocks
- `Stalker.addCallProbe(target, callback)` — fire when a specific function is called (regardless of how)
- `DRCOV` export format — coverage files compatible with IDA Lighthouse, Bruteforce Logic, radare2

**SAB integration point**: the Stalker hook callback writes events into a `SharedRingBuffer` (borrowed from `extensions/hexcore-common/src/sharedRingBuffer.ts`), just like the existing `CodeHookSabCB` in hexcore-unicorn. This gives Elixir's instrumentation 1.34× throughput and 100% delivery from day one — no separate performance work needed.

### Agent Runtime (`agents/src/`)

The existing TypeScript stub (~150 lines across `interceptor.ts`, `stalker.ts`, `memory.ts`, `process.ts`) is the right surface. Fill in the implementations by calling into the NAPI bridge. Keep the API shape close to Frida's but rename namespaces to `Elixir.Interceptor`, `Elixir.Stalker`, etc. for license and brand clarity.

### Acceptance criteria

- `Elixir.Interceptor.attach(0x140002430, { onEnter: log, onLeave: log })` fires twice when the v3 malware calls the intercepted function
- `Elixir.Stalker.follow()` produces a DRCOV file openable in IDA Lighthouse
- Sample agent script: "Log every `Sleep()` call with its duration argument" — works in under 30 lines of TS
- Throughput: ≥ 500k blocks/sec for empty Stalker follow (matching SAB zero-copy baseline)

### Effort: ~5 weeks

---

## Phase 5 — Integration (v0.5.x) — ~3 weeks

**Goal:** Elixir ships as a thin wrapper extension in the HexCore monorepo, following the Helix pattern. The standalone repo publishes a GitHub Release with the prebuilt `.node`; the wrapper downloads it at install time.

**The swarm does NOT implement Phase 5.** The monorepo maintainer writes the wrapper (~300-500 lines) once the swarm delivers a working standalone repo with all Gates passing. This is faster than specifying the wrapper in enough detail for a swarm to write it correctly.

### Gate check

- All five G1–G5 tests pass in the Elixir CI
- `elixir-cli` matches hexcore-debugger's apiCalls trace on all three malware versions
- No regression on existing hexcore-debugger test suites (those stay green until retired)

### Files to add IN THE MONOREPO (maintainer does this, not the swarm)

- `extensions/hexcore-elixir/` — new VS Code extension, Helix-pattern wrapper
- `extensions/hexcore-elixir/package.json` — declares the extension, lists `contributes.commands`, runs `hexcore-native-install.js` at `postinstall`
- `extensions/hexcore-elixir/src/extension.ts` — activation, imports the downloaded `.node`, registers `hexcore.elixir.emulate`, `hexcore.elixir.stalk`, `hexcore.elixir.intercept` commands
- `extensions/hexcore-elixir/src/emulationPanel.ts` — UI port from hexcore-debugger's emulation panel (API call trace, register display, memory inspector)
- `extensions/hexcore-elixir/scripts/hexcore-native-install.js` — copy of the Helix install script pattern, downloads the Elixir `.node` from `github.com/AkashaCorporation/HexCore-Elixir` releases
- Hooks into existing `hexcore-pipeline` job schema so `{ "cmd": "hexcore.elixir.emulate" }` becomes a drop-in replacement for `hexcore.debugger.emulateFullHeadless`

### Shipping to users (3.8.0 stable)

Following HexCore's "ship working, polish in follow-ups" philosophy (the same approach that shipped SAB/Perseus while Unicorn still had `UC_ERR_*` regressions from earlier versions), Elixir ships inside **HexCore 3.8.0 stable** as the primary emulation path alongside the legacy `hexcore-debugger`.

- `hexcore.emulator = "azoth" | "debugger"` setting, **default `"azoth"`**
- `hexcore-debugger` TypeScript path remains installed but un-advertised, available via the setting for regression comparison
- Polish happens in v3.8.1+: additional Win32 API coverage, Linux syscall breadth, Mach-O loader, fuzzing harness integration

### Snapshot & time-travel (bonus)

- `Elixir.Snapshot.save()` captures full emulator state (memory pages, registers, VFS state, registry state)
- `Elixir.Snapshot.restore()` rewinds deterministically
- Fuzzing harness: takes a snapshot at `main()`, mutates input, restores, re-runs — classic AFL++/libFuzzer-style without a process fork
- **Depends on Phase 1 memory manager having page-level dirty tracking** (add the bit during Phase 1 to avoid a rewrite here)

### Fuzzing harness

- CLI: `elixir fuzz <binary> --target-func 0x140002430 --input-addr 0x5000020 --snapshot main`
- Uses Stalker coverage to guide input mutation
- Produces corpus + crash dumps in the same format as libFuzzer for tool interop

### Effort: ~3 weeks

---

## Cross-cutting Concerns

### Dependency lock
| Component | Current version | Owner |
|---|---|---|
| hexcore-unicorn | 1.2.3 | Monorepo `extensions/hexcore-unicorn/` |
| SAB ring buffer | v1 (shipped 2026-04-11) | Monorepo `extensions/hexcore-common/src/sharedRingBuffer.ts` |
| Rust toolchain | stable (see `rust-toolchain.toml`) | Elixir repo |
| C++ standard | C++23 | Elixir repo |
| NAPI-RS | ^2.16 | Elixir repo |
| CMake | 3.20+ | Elixir repo |

### Build topology
```
 HexCore monorepo              HexCore-Elixir standalone
 ───────────────              ────────────────────────
 hexcore-unicorn              engine/ (C++23)
       │                            │
       │    (linked as              │
       │     static lib)            │
       └───────────────────────►    ├── crates/elixir-core (FFI)
                                    ├── crates/hexcore-elixir (NAPI)
                                    └── agents/ (TS)
                                           │
   HexCore monorepo ◄───────────────── extensions/hexcore-elixir/
   (when Phase 5 ships)                 (imports the .node from
                                         crates/hexcore-elixir)
```

### License audit

- **Allowed to reference**: frida-gum concepts (wxWindows-style permissive), DynamoRIO papers (BSD-3), academic PLDI/OSDI/USENIX instrumentation papers, Microsoft PE spec, ELF spec, Apple Mach-O docs, MSDN documentation, man pages, UAPI headers
- **Forbidden to reference or port**: Qiling source (GPLv3), any code lifted from Frida's GPL-licensed tools (not frida-gum itself, but frida-core and frida-tools), any code under LGPL without express separation
- **Reviewed before merge**: every contribution touching `engine/src/os/` or `engine/src/loader/` must declare its reference sources in the PR description

### Continuous validation gate

Every PR runs:
1. The full Phase-1 test suite
2. The Parity Gate G1–G5 (when the respective phases land, earlier gates are regression-protected)
3. Clippy + rustfmt + clang-tidy on changed files
4. SAB ring buffer sanity test (no drops under `100k events/sec`)

---

## Priority Matrix

| # | Feature | Phase | Priority | Effort | Depends on | Status |
|---|---|---|---|---|---|---|
| 1.1 | Unicorn wiring in core | 1 | **P0** | 1 week | — | 📋 Stub exists |
| 1.2 | Memory manager | 1 | **P0** | 1 week | 1.1 | 📋 Stub exists |
| 1.3 | Rust FFI bridge | 1 | **P0** | 3 days | 1.1 | 📋 Stub exists |
| 1.4 | NAPI-RS bridge | 1 | **P0** | 3 days | 1.3 | 📋 Stub exists |
| 1.5 | elixir-cli | 1 | **P1** | 3 days | 1.4 | ⬜ |
| 2.1 | PE64 loader | 2 | **P0** | 2 weeks | 1.2 | 📋 Stub exists |
| 2.2 | Data-import detection port | 2 | **P0** | 2 days | 2.1 | ⬜ Reference ready (peLoader.ts) |
| 2.3 | PEB_LDR_DATA setup port | 2 | **P0** | 1 day | 2.1 | ⬜ Reference ready (peLoader.ts) |
| 2.4 | ELF64 ET_EXEC loader | 2 | **P1** | 1 week | 1.2 | 📋 Stub exists |
| 2.5 | ELF64 ET_REL (kernel module) | 2 | **P1** | 1 week | 2.4 | ⬜ |
| 2.6 | Mach-O loader (basic) | 2 | **P3** | 1 week | 1.2 | 📋 Stub exists |
| 3.1 | Win32 API hooks (35 critical) | 3 | **P0** | 2 weeks | 2.1 | ⬜ Reference ready (winApiHooks.ts) |
| 3.2 | CRT init + exit stubs port | 3 | **P0** | 3 days | 3.1 | ⬜ Reference ready |
| 3.3 | TEB/PEB + PEB_LDR_DATA | 3 | **P0** | 2 days | 2.1 | ⬜ Reference ready |
| 3.4 | Linux syscall dispatch | 3 | **P1** | 1 week | 2.4 | 📋 Stub exists |
| 3.5 | VFS | 3 | **P1** | 1 week | 3.1 | 📋 Stub exists |
| 3.6 | Registry | 3 | **P1** | 4 days | 3.1 | 📋 Stub exists |
| 4.1 | Interceptor | 4 | **P0** | 2 weeks | 3.1 | 📋 Stub exists |
| 4.2 | Stalker | 4 | **P0** | 1 week | 4.1 | 📋 Stub exists |
| 4.3 | SAB ring buffer integration | 4 | **P0** | 3 days | 4.2 | ⬜ Reference: `sharedRingBuffer.ts` |
| 4.4 | Agent runtime (TS) | 4 | **P1** | 1 week | 4.1, 4.2 | 📋 Stub exists |
| 4.5 | DRCOV export | 4 | **P2** | 3 days | 4.2 | ⬜ |
| 5.1 | Parity Gate G1–G5 | 5 | **P0** | 1 week | 3.2, 3.3 | ⬜ Gate is the ship criterion |
| 5.2 | VS Code extension shell | 5 | **P0** | 4 days | 5.1 | ⬜ |
| 5.3 | Pipeline command integration | 5 | **P0** | 3 days | 5.2 | ⬜ |
| 5.4 | Snapshot save/restore | 5 | **P1** | 1 week | 1.2 (dirty page tracking) | 📋 Stub exists |
| 5.5 | Fuzzing harness | 5 | **P2** | 1 week | 5.4, 4.2 | ⬜ |

### Total effort estimate
- Phase 1: 3 weeks
- Phase 2: 4 weeks
- Phase 3: 6 weeks
- Phase 4: 5 weeks
- Phase 5: 3 weeks (after gate passes)
- **Total: ~21 weeks (5 months) solo, ~12 weeks paired**

---

## What Elixir is NOT (to prevent scope creep)

- **Not a full Windows kernel emulator** — no NT executive, no HAL, no driver framework. Ring-3 user-mode only for v0.x; kernel-mode is a v1.x consideration only if the `mali_kbase.ko` path proves the ELF/syscall design first.
- **Not a disassembler or decompiler** — that's Pathfinder + Helix + Remill in the main monorepo. Elixir consumes their output if needed but does not replicate them.
- **Not a YARA engine, IOC extractor, or string analyzer** — those stay in `extensions/hexcore-*` in the main repo. Elixir provides the runtime events; the analysis extensions consume them via the SAB bridge.
- **Not a replacement for hexcore-unicorn** — Elixir *depends* on hexcore-unicorn. It adds OS personality and instrumentation on top.
- **Not a Frida replacement for non-emulation targets** — Elixir is instrumentation *inside* an emulator. Live process attach to a real running program is explicitly out of scope.

---

## Decision Log (updates with each phase)

| Date | Decision | Rationale |
|---|---|---|
| 2026-04-11 | Skeleton scaffolded with 4-tier architecture | Qiling-style layering with clean-room discipline |
| 2026-04-14 | Parity Gate (G1–G5) adopted as ship criterion instead of "feature complete" checklist | Ground-truth traces from hexcore-debugger's successful malware run give objective, measurable targets |
| 2026-04-14 | hexcore-debugger continues as primary path until gate passes | Avoid splitting effort between two broken emulators; maintain the working path until Elixir is equally capable |
| 2026-04-14 | SAB ring buffer is a consumption dependency, not a development task for Elixir | Already shipped and working in hexcore-unicorn; Elixir integrates via existing `SharedRingBuffer` class |
| 2026-04-14 | Reference reading from hexcore-debugger TS code is allowed; copy-paste is not | Clean-room for license, but we don't waste months re-deriving PEB_LDR_DATA layout that's already documented in the monorepo |
| 2026-04-14 | Codename adopted: **Project Azoth 🜇** | Continues the HexCore hidden-arts theming started by Project Perseus (SAB). Azoth = alchemical mercury, the animating spirit of transformation — matches Elixir's role of transforming static bytes into observable dynamic behavior |
| 2026-04-14 | Delivery pattern confirmed as Helix-style wrapper | Standalone repo hosts all Rust/C++/NAPI code. HexCore monorepo hosts only a thin TS wrapper (~300-500 lines) that downloads the `.node` at `postinstall`. Zero vendor dump in vscode-main. |
| 2026-04-14 | Ship target is HexCore 3.8.0 stable, not 3.8.1+ | HexCore's "ship working, polish in follow-ups" philosophy — SAB/Perseus shipped alongside Unicorn UC_ERR regressions from earlier versions. Azoth ships with `hexcore.emulator` setting defaulting to "azoth", with "debugger" available for regression comparison |

---

## Appendix A — Why the Parity Gate is the right ship criterion

Traditional "feature complete" checklists fail because:
1. Every emulator author invents a new notion of "done"
2. Binaries in the wild do weird things that no checklist predicts (e.g. reading `std::cout` as data, which crashed hexcore-debugger until 2026-04-14)
3. Subtle bugs (BigInt sign extension, missing CRT stubs, missing PEB_LDR_DATA) manifest only when running real targets

The Parity Gate sidesteps all three:
1. "Done" = "the reference implementation works AND Elixir reproduces its behavior within 5% deviation"
2. Real binaries *are* the acceptance suite
3. If a subtle bug exists in Elixir, the deviation from hexcore-debugger's ground-truth trace exposes it immediately

The gate is also self-updating: as hexcore-debugger adds support for more targets (e.g., `vgk.sys` anti-cheat, `kgsl.c` Qualcomm GPU driver), those become new gate entries automatically. Elixir chases a moving target in the best sense — it inherits the monorepo's accumulating ground-truth every time someone adds a test.

---

## Appendix B — Immediate next actions (week of 2026-04-14)

This is the unordered TODO for the *next* coding session on Elixir itself, independent of the main monorepo work:

1. Add `unicorn.h` include path to `engine/CMakeLists.txt`. Link against `hexcore-unicorn` static lib.
2. Make `elixir_create` actually call `uc_open(UC_ARCH_X86, UC_MODE_64, &ctx->uc)`.
3. Make `elixir_mem_map` call `uc_mem_map`.
4. Make `elixir_run` call `uc_emu_start` with the correct arguments.
5. Write `tests/phase1_sanity.rs` — map a page, write `48 c7 c0 41 00 00 00 c3` (mov rax,0x41; ret), run, assert rax == 0x41.
6. `cargo test -p elixir-core` green.

That's Phase 1.1 — probably 4–6 hours of focused work. After that the real phasing begins.
