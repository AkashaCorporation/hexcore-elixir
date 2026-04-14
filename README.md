# HexCore Elixir

> **Codename: 🜇 Project Azoth** — in alchemy, Azoth is mercury, the animating spirit of transformation. The HexCore hidden-arts codename lineage: Project Perseus (SAB zero-copy IPC) → Project Azoth (dynamic analysis engine).

**Elixir** is the advanced dynamic analysis, emulation, and instrumentation framework behind [HexCore](https://github.com/AkashaCorporation/HikariSystem-HexCore). It is built on top of [HexCore-Unicorn](https://github.com/AkashaCorporation/hexcore-unicorn) and provides a clean-room, Apache-2.0 licensed OS emulation layer.

Elixir was designed from the ground up to replace GPLv3 frameworks like Qiling, offering full cross-platform OS emulation (loaders, syscalls, VFS) combined with powerful, scriptable dynamic instrumentation concepts pioneered by Frida.

## What Elixir Does

- **CPU Emulation** — Drives execution through HexCore-Unicorn with advanced memory fault handling and JIT block caching.
- **Clean-Room OS Emulation** — Implements PE/ELF/Mach-O loaders, thread management, and syscall routing from scratch. No GPL code.
- **Frida-Style Instrumentation** — Built-in Interceptor API for inline hooking, memory access tracking, and Stalker-like basic block tracing directly at the emulation layer.
- **Virtual Environment Mocking** — Fully isolated Virtual File System (VFS), fake Windows Registry, and mock network sockets.
- **Snapshot & Restore** — Deterministic memory and CPU context snapshotting for fuzzing and time-travel debugging.
- **Cross-Architecture** — Supports x86, x86_64, ARM, and ARM64 out of the box.

## Architecture

Elixir operates in a 4-tier architecture:

| Tier | Name | Description |
|------|------|-------------|
| 1 | **elixir_core** | Execution loop, memory manager, HexCore-Unicorn bindings |
| 2 | **elixir_ldr** | Binary format parsers (PE, ELF, Mach-O), section mapping, import resolution, TLS |
| 3 | **elixir_os** | OS personality — syscall dispatch, POSIX/Win32 handlers, VFS, registry |
| 4 | **elixir_agent** | Instrumentation bridge — JS/Rust agents hook functions, read/write memory, manipulate registers |

```
  agents/ (JS/TS)  ──►  crates/hexcore-elixir (NAPI-RS)  ──►  crates/elixir-core (Rust FFI)  ──►  engine/ (C++23)
                                                                                                       │
                                                                                                  HexCore-Unicorn
```

## Repository Layout

```
HexCore-Elixir/
├── engine/                 C++23 core engine, loaders, OS subsystems, CLI
├── crates/                 Rust workspace — elixir-core + NAPI bridge
├── agents/                 TypeScript/JS agent runtime (Frida-style API)
├── tests/                  Integration fixtures, target binaries, and fuzzers
├── ARCHITECTURE.md         Architectural overview
├── CHANGELOG.md            Release notes
└── roadmap.md              Near-term roadmap
```

## Build Prerequisites

- **Rust** stable (via rustup)
- **Node.js** 22+
- **CMake** 3.20+
- A **C++23** toolchain (MSVC 2022 / GCC 13+ / Clang 16+)
- **HexCore-Unicorn** (pulled automatically via git submodules or Rust build script)

## Build

### 1. Build the C++ engine

```bash
cmake -B engine/build -S engine -DCMAKE_BUILD_TYPE=Release
cmake --build engine/build --config Release
```

### 2. Build the Rust + NAPI bridge

```bash
npm install
npm run build
```

### 3. Run the CLI

```bash
# Emulate a Linux ELF with an instrumentation script
./engine/build/Release/elixir_tool run target_bin --os linux --script agent.js

# Emulate a Windows PE and drop into a shell at entry point
./engine/build/Release/elixir_tool run target.exe --os windows --interactive
```

## Agent Example

```typescript
import { Interceptor, Process } from '@hexcore/elixir-agents';

const mod = Process.findModuleByName('libc.so.6');
const malloc = mod?.exports.find(e => e.name === 'malloc');

if (malloc) {
    Interceptor.attach(malloc.address, {
        onEnter(ctx) {
            console.log(`[malloc] size = ${ctx.args[0]}`);
        },
        onLeave(ctx) {
            console.log(`[malloc] => 0x${ctx.returnValue!.toString(16)}`);
        }
    });
}
```

## Clean-Room Policy

This project is **Apache-2.0** licensed. No code from GPLv3 sources (Qiling, Frida-core) has been used. OS behavior is implemented from public specifications (Microsoft PE/COFF spec, ELF spec, MSDN, Linux man pages). Instrumentation concepts reference frida-gum (wxWindows/permissive license) and DynamoRIO (BSD-3-Clause).

## License

Apache-2.0 — see [LICENSE](LICENSE).

---

Built by [Akasha Corporation](https://github.com/AkashaCorporation)
