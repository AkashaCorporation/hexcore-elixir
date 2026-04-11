# HexCore Elixir — Architecture

## 4-Tier Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Tier 4: elixir_agent (Instrumentation Bridge)          │
│  agents/src/ — Interceptor, Stalker, Memory, Process    │
│  JS/TS agents hook functions and manipulate state        │
├─────────────────────────────────────────────────────────┤
│  Tier 3: elixir_os (OS Personality)                     │
│  engine/src/os/ — Syscall dispatch, API hooks, VFS      │
│  Linux (POSIX), Windows (NTDLL/Win32), macOS (Mach)     │
├─────────────────────────────────────────────────────────┤
│  Tier 2: elixir_ldr (Binary Loader)                     │
│  engine/src/loader/ — PE, ELF, Mach-O parsers           │
│  Section mapping, import resolution, TLS setup          │
├─────────────────────────────────────────────────────────┤
│  Tier 1: elixir_core (Execution Engine)                 │
│  engine/src/core/ — Unicorn bindings, memory manager    │
│  CPU emulation, page fault handling, JIT block cache    │
└─────────────────────────────────────────────────────────┘
         │
         ▼
   HexCore-Unicorn (CPU engine, separate package)
```

## Build Flow

```
CMake (engine/)          Rust (crates/)              Node.js
     │                        │                        │
     ▼                        ▼                        ▼
elixir_engine.lib  ──►  elixir-core (FFI)  ──►  hexcore-elixir.node
                        (build.rs links)        (NAPI-RS cdylib)
```

## Clean-Room Policy

This project is Apache-2.0 licensed. No code from GPLv3 sources (Qiling, Frida-core)
has been used. OS behavior is implemented from public specifications:

- PE/ELF/Mach-O: Microsoft PE spec, ELF spec, Apple docs
- Windows APIs: MSDN documentation
- Linux syscalls: man pages, UAPI headers
- Instrumentation concepts: frida-gum (wxWindows/permissive), DynamoRIO (BSD-3), academic papers
