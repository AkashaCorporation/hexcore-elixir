# Vendored dependency — hexcore-unicorn

## Provenance

- **Source**: `vscode-main/extensions/hexcore-unicorn/` (HexCore monorepo)
- **Vendored on**: 2026-04-14
- **hexcore-unicorn version**: **1.2.3-nightly** (ahead of the 1.2.1 currently on npm)
- **Unicorn upstream version**: 2.0.1 (via the embedded `deps/unicorn/`)
- **Target platform**: win32-x64 (Windows 64-bit only in this vendor)

## Why vendored instead of `npm i`?

The npm registry ships hexcore-unicorn 1.2.1, which is two versions behind:
- **1.2.2** added the SharedArrayBuffer zero-copy CODE hook path (`CodeHookSabCB` + `hookAddSAB`) — essential for Elixir's Stalker design in Phase 4.
- **1.2.3** added BigInt write masking in `RegWrite`/`RegWriteBatch` — prevents sign-extension crashes when emulating MSVC CRT code that calls `QueryPerformanceCounter` / `GetTickCount`.

The updated version will ship to npm after HexCore 3.8.0 stable releases. Until then, the Elixir development swarm consumes this vendored copy to avoid blocking on the npm release cycle.

**When npm catches up**: delete this directory and replace with `"hexcore-unicorn": "^1.2.3"` in the appropriate `package.json` (or a Rust crate equivalent). The API surface is identical — this is the same binary that will ship to npm.

## What's here

```
deps/hexcore-unicorn/
├── src/                            # Reference wrapper source (READ, don't compile)
│   ├── unicorn_wrapper.cpp         # The NAPI/C++ wrapper Elixir's engine.cpp mirrors conceptually
│   ├── unicorn_wrapper.h
│   ├── emu_async_worker.h          # Async emulation worker pattern
│   └── main.cpp                    # NAPI module entry
├── include/unicorn/                # Unicorn 2.0.1 C API headers (COMPILE against these)
│   ├── unicorn.h
│   ├── x86.h
│   ├── arm.h / arm64.h
│   └── ... (all supported arches)
├── lib/                            # Import library for Windows linking
│   └── unicorn-import.lib          # ~10 KB — links against unicorn.dll at load
├── bin/                            # Runtime binary
│   └── unicorn.dll                 # ~34 MB — required at runtime; place next to .exe/.node
├── test/                           # Reference test suite (READ, adapt for Elixir's own tests)
│   ├── test.js                     # 29 Unicorn wrapper tests — Phase 1 sanity target
│   ├── test_sab_hook.js            # SharedArrayBuffer hook path — Phase 4 reference
│   ├── test_sab_benchmark.js       # SAB throughput benchmark target
│   ├── test_shared_mem.js          # Shared memory primitives
│   └── test_bps.js                 # Breakpoint semantics
├── binding.gyp                     # node-gyp build config (reference for NAPI layout)
├── index.js / index.mjs / index.d.ts  # NAPI JavaScript API surface
├── package.json.reference          # Renamed to avoid confusing Node's resolver
├── README.md.reference
└── VERSION.md                      # This file
```

## What's NOT here

- **Full Unicorn upstream source** — not needed for vendored dev. If you need to debug into Unicorn itself, clone `github.com/unicorn-engine/unicorn` separately.
- **Prebuilds for other platforms** — Windows-only in this vendor. Linux support comes in a second vendoring pass (or when Elixir CI moves to Linux runners).
- **`build/` intermediate artifacts** — regenerable via CMake/node-gyp.
- **`node_modules/`** — irrelevant; Elixir consumes this as C/C++ source, not as an npm package.

## License

- `src/unicorn_wrapper.cpp` and friends: MIT (from HexCore monorepo)
- `include/unicorn/*.h` and `lib/unicorn-import.lib` and `bin/unicorn.dll`: GPLv2 with linking exception (Unicorn upstream)
- Elixir's relationship: Elixir consumes the Unicorn GPL code via dynamic linking (unicorn.dll). The linking exception permits Apache-2.0 code (Elixir) to link against the GPL binary without inheriting GPL terms.

**Do NOT copy verbatim** from `src/unicorn_wrapper.cpp` into Elixir's `engine/src/core/engine.cpp`. The wrapper is a reference implementation — read it, understand the patterns, and write equivalent Rust/C++ from scratch to preserve Elixir's clean-room status. Identifier names and comments that appear in Elixir source must not be lifted from the reference.

## Clean-room policy for this vendored copy

| Action | Allowed? |
|---|---|
| Read `src/unicorn_wrapper.cpp` to understand the CODE hook + SAB pattern | ✅ Yes |
| Copy a function signature (e.g. `static bool InvalidMemHookCB(...)`) | ❌ No — write your own |
| Port the idea of "auto-map on fault with a < 0x1000 NULL guard" | ✅ Yes (the idea, not the code) |
| Include `unicorn/unicorn.h` from `deps/hexcore-unicorn/include/` | ✅ Yes |
| Link against `unicorn-import.lib` + ship `unicorn.dll` alongside | ✅ Yes |
| Call `uc_open`, `uc_emu_start`, `uc_hook_add` from Elixir's engine.cpp | ✅ Yes |
| Copy the test harness layout verbatim from `test/test.js` | ❌ No — inspired-by is fine, verbatim is not |

## Intended consumers

- `../../engine/CMakeLists.txt` — adds `include/` to the include path and links against `lib/unicorn-import.lib`
- `../../crates/elixir-core/build.rs` — optionally copies `bin/unicorn.dll` next to the Rust output so runtime dynamic linking works
- The swarm that implements Phases 1–4 reads everything in this directory as reference material

When Elixir reaches Phase 5 and is ready to be integrated into the HexCore monorepo, this vendored copy is deleted and the real package dependency takes over.
