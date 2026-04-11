# HexCore Elixir — Roadmap

## Phase 1: Core Engine (v0.1.x)
- [ ] Wire Unicorn engine in C++ core (create, mem_map, emu_start)
- [ ] Memory manager with heap allocator and fault handler
- [ ] Rust FFI bridge to C++ engine
- [ ] NAPI-RS bridge exposing Emulator to JS

## Phase 2: Loaders (v0.2.x)
- [ ] ELF loader (static binaries first)
- [ ] PE loader (PE32+ executables)
- [ ] Import resolution with hook stubs
- [ ] Mach-O loader (basic support)

## Phase 3: OS Emulation (v0.3.x)
- [ ] Linux syscall dispatch (read, write, mmap, brk, exit)
- [ ] Linux libc hooks (printf, malloc, strlen, etc.)
- [ ] Windows NTDLL syscall dispatch
- [ ] Windows API hooks (Kernel32, KernelBase)
- [ ] PEB/TEB setup
- [ ] Virtual File System (VFS)
- [ ] Windows Registry emulation

## Phase 4: Instrumentation (v0.4.x)
- [ ] Interceptor: attach/detach/replace via Unicorn hooks
- [ ] Stalker: basic block tracing via UC_HOOK_BLOCK
- [ ] Agent script loading and execution
- [ ] DRCOV export for coverage visualization

## Phase 5: Integration (v0.5.x)
- [ ] VS Code extension (extensions/hexcore-elixir/)
- [ ] HexCore IDE integration (emulation panel, hook UI)
- [ ] Snapshot save/restore for time-travel debugging
- [ ] Fuzzing harness
