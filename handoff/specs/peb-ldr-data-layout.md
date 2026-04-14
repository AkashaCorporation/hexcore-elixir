# TEB / PEB / PEB_LDR_DATA Memory Layout

## Why this matters

Hand-rolled PEB walkers are used by:
- MSVC CRT itself (`GetModuleHandle(NULL)` implementations, some internal checks)
- Anti-analysis malware (walks PEB→Ldr→InMemoryOrderModuleList to find loaded DLLs without importing `LoadLibrary`)
- Shellcode loaders, packers, metamorphic engines
- djb2-style API hash resolvers (HEXCORE_DEFEAT v3 "Ashaka Shadow")

If your emulator maps TEB and PEB but leaves `PEB.Ldr` (offset 0x18 on x64, 0x0C on x86) as zero, every PEB walker will fault:

```asm
mov rax, gs:[0x60]      ; rax = PEB
mov r14, [rax+0x18]     ; r14 = PEB->Ldr → ZERO
add r14, 0x20           ; r14 = 0x20
mov rbx, [r14]          ; read [0x20] → UC_ERR_READ_UNMAPPED (NULL page)
```

This spec provides the minimal viable PEB_LDR_DATA structure that makes PEB walkers **exit cleanly without executing a real walk**.

## Memory region constants

The reference implementation uses these fixed addresses. You can pick your own as long as they're consistent, don't collide with PE image sections, and are mapped R/W.

| Symbol | Address (x64) | Size | Purpose |
|---|---|---|---|
| `STUB_BASE` | `0x70000000` | 1 MB | API hook stubs (16 bytes each) |
| `DATA_IMPORT_BASE` | `0x71000000` | 8 MB | C++ data import blocks (4 KB each) |
| `TLS_STORAGE_BASE` | `0x7FFB0000` | 64 KB | TLS callback storage |
| `TLS_VECTOR_ADDRESS` | `0x7FFC0000` | 64 KB | ThreadLocalStoragePointer array |
| `PEB_ADDRESS` | `0x7FFD0000` | 4 KB | Process Environment Block |
| `TEB_ADDRESS` | `0x7FFDE000` | 8 KB | Thread Environment Block |
| `DEFAULT_STACK_BASE` | `0x7FFF0000` | 1 MB | Thread stack |

All of these are within the "Windows user-mode high memory" convention. The canonical Windows process leaves `0x7FFD0000`–`0x7FFFFFFF` for TEB/PEB/system structures, so using these addresses matches what Win32 APIs see.

## TEB64 layout (NT_TIB64 + Teb64)

Write a zero-filled 8 KB block at `TEB_ADDRESS`, then populate these fields:

| Offset | Size | Field | Value |
|---|---|---|---|
| 0x08 | 8 | StackBase | `DEFAULT_STACK_TOP` (= 0x7FFF0000 + 0x100000) |
| 0x10 | 8 | StackLimit | `DEFAULT_STACK_BASE` (= 0x7FFF0000) |
| 0x30 | 8 | Self (pointer to TEB) | `TEB_ADDRESS` |
| 0x40 | 4 | ClientId.UniqueProcess | `0x1000` (fake PID) |
| 0x48 | 4 | ClientId.UniqueThread | `0x1004` (fake TID) |
| 0x58 | 8 | ThreadLocalStoragePointer | `TLS_VECTOR_ADDRESS` |
| 0x60 | 8 | ProcessEnvironmentBlock | `PEB_ADDRESS` |

Then set the `gs_base` register to `TEB_ADDRESS`. Unicorn supports this on x86_64 via:

```c
uc_x86_msr msr = { .rid = 0xC0000101, .value = TEB_ADDRESS }; // IA32_GS_BASE
uc_reg_write(uc, UC_X86_REG_MSR, &msr);
```

(Different Unicorn versions expose `UC_X86_REG_GS_BASE` as a direct register — check your Unicorn 2.0.1 headers in `deps/hexcore-unicorn/include/unicorn/x86.h`.)

## PEB64 layout

Write a zero-filled 4 KB block at `PEB_ADDRESS`, then populate:

| Offset | Size | Field | Value |
|---|---|---|---|
| 0x02 | 1 | BeingDebugged | `0` (anti-anti-debug: pretend not under a debugger) |
| 0x10 | 8 | ImageBaseAddress | `image_base` (from the loaded PE) |
| **0x18** | **8** | **Ldr** (PPEB_LDR_DATA) | **`PEB_ADDRESS + 0x200`** |

The critical field is **offset 0x18** — without it, PEB walkers fault instantly.

## PEB_LDR_DATA layout (at PEB + 0x200)

Write a `PEB_LDR_DATA` structure inside the PEB page itself, at offset 0x200 (gives you ~3.5 KB of headroom in the PEB page for anything else you want to put there later).

The x64 layout is 0x58 bytes:

| Offset from LDR_DATA base | Size | Field | Value |
|---|---|---|---|
| 0x00 | 4 | Length | `0x58` |
| 0x04 | 1 | Initialized | `1` (TRUE) |
| 0x08 | 8 | SsHandle | `0` (NULL — system-allocated handle, not needed) |
| 0x10 | 8 | InLoadOrderModuleList.Flink | `(LDR_DATA_base + 0x10)` — **self** |
| 0x18 | 8 | InLoadOrderModuleList.Blink | `(LDR_DATA_base + 0x10)` — **self** |
| 0x20 | 8 | InMemoryOrderModuleList.Flink | `(LDR_DATA_base + 0x20)` — **self** |
| 0x28 | 8 | InMemoryOrderModuleList.Blink | `(LDR_DATA_base + 0x20)` — **self** |
| 0x30 | 8 | InInitializationOrderModuleList.Flink | `(LDR_DATA_base + 0x30)` — **self** |
| 0x38 | 8 | InInitializationOrderModuleList.Blink | `(LDR_DATA_base + 0x30)` — **self** |
| 0x40 | 8 | EntryInProgress | `0` |
| 0x48 | 1 | ShutdownInProgress | `0` |
| 0x50 | 8 | ShutdownThreadId | `0` |

## The empty-list trick

Each `LIST_ENTRY` is `{ Flink; Blink }` — 16 bytes on x64. For each of the three module lists (`InLoadOrder`, `InMemoryOrder`, `InInitializationOrder`), we set both `Flink` and `Blink` to point to the list entry itself. This creates an **empty circular doubly-linked list**.

The canonical Windows PEB walker pattern is:

```c
PPEB peb = (PPEB)__readgsqword(0x60);
PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
PLIST_ENTRY curr = head->Flink;
while (curr != head) {
    PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    // ... process entry ...
    curr = curr->Flink;
}
```

With the empty-list layout:
- `head = &peb->Ldr->InMemoryOrderModuleList` = `LDR_DATA_base + 0x20`
- `curr = head->Flink` = `[LDR_DATA_base + 0x20]` = `LDR_DATA_base + 0x20`
- `curr == head` → true → loop exits on the very first iteration

The walker returns without finding any DLLs. Code that calls `ResolveApiByHash(x)` will then return NULL or its failure sentinel, and downstream code either handles that gracefully or calls the NULL pointer (which your CODE hook can intercept to identify which hash was being resolved — useful for Phase 5 analysis features).

## PEB32 layout (if you need to support x86)

The x86 layout is similar but tighter:

| Offset | Size | Field | Value |
|---|---|---|---|
| 0x02 | 1 | BeingDebugged | `0` |
| 0x08 | 4 | ImageBaseAddress | `image_base` (32-bit) |
| 0x0C | 4 | Ldr | `PEB_ADDRESS + 0x200` (32-bit) |

PEB_LDR_DATA32 layout (at PEB + 0x200):

| Offset | Size | Field | Value |
|---|---|---|---|
| 0x00 | 4 | Length | `0x30` |
| 0x04 | 1 | Initialized | `1` |
| 0x08 | 4 | SsHandle | `0` |
| 0x0C | 4 | InLoadOrderModuleList.Flink | `self + 0x0C` |
| 0x10 | 4 | InLoadOrderModuleList.Blink | `self + 0x0C` |
| 0x14 | 4 | InMemoryOrderModuleList.Flink | `self + 0x14` |
| 0x18 | 4 | InMemoryOrderModuleList.Blink | `self + 0x14` |
| 0x1C | 4 | InInitializationOrderModuleList.Flink | `self + 0x1C` |
| 0x20 | 4 | InInitializationOrderModuleList.Blink | `self + 0x1C` |

## Verification test

Write a minimal PEB walker and emulate it. The walker should terminate cleanly.

```asm
; x64, assembles to something like:
;   48 65 8b 04 25 60 00 00 00   mov rax, gs:[0x60]
;   48 8b 48 18                   mov rcx, [rax+0x18]
;   48 83 c1 20                   add rcx, 0x20
;   48 8b 01                      mov rax, [rcx]
;   48 39 c1                      cmp rcx, rax
;   74 02                         je done
;   eb fa                         jmp -6 (walk next entry)
;   done:
;   c3                            ret
```

Expected: no fault, walker RETs after 1 iteration. Instructions executed: ~6.

## Non-negotiable requirements

1. `PEB.Ldr` at offset 0x18 (x64) / 0x0C (x86) **must** be non-zero and point to a mapped, readable region.
2. The `PEB_LDR_DATA.Length` field **must** match the architecture (0x58 on x64, 0x30 on x86).
3. All three `LIST_ENTRY` pairs **must** self-reference. Any other value will either crash on first read or loop forever.
4. `gs_base` register **must** be set to `TEB_ADDRESS` before `uc_emu_start`. Without this, `gs:[0x60]` reads from effective address `TEB_ADDRESS + 0x60` via segment translation — but if `gs_base` is 0, the read falls into the NULL page and faults.

## Known gotcha: `setRegisterSync('gs_base', TEB_ADDRESS)` silently fails

Some Unicorn builds do not expose `gs_base` as a writable register under that name. If the reference implementation's try/catch swallows a failure here, the emulator appears to work for a few instructions then mysteriously faults the first time anything touches `gs:[N]`.

**Fix**: use the MSR interface (`IA32_GS_BASE = 0xC0000101`) via `uc_msr` or an equivalent direct MSR write. Always verify by reading back `gs_base` after the write; if the read returns 0, the write silently failed and you need a different API.

```c
// Verification pattern (pseudocode)
uc_reg_write_gs_base(uc, TEB_ADDRESS);
uint64_t readback = uc_reg_read_gs_base(uc);
assert(readback == TEB_ADDRESS);
```

## Reference origin

This layout was discovered on 2026-04-14 while tracing the `Malware HexCore Defeat.exe` v3 "Ashaka Shadow" crash at instruction 781. The source code of the sample includes this PEB walker:

```cpp
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;
    while (curr != head) { ... }
```

Which compiles to a `mov rax, [PEB+0x18]; add rax, 0x20; mov rbx, [rax]` sequence. Without `PEB.Ldr` initialized, this faults at `mov rbx, [0x20]`.

After implementing the empty-list fix, the malware's `ResolveApiByHash` returned without crashing, and the entire binary ran to its 1M instruction emulation cap with 23,128 API calls captured — the full anti-debug, anti-VM, and timing check payload.
