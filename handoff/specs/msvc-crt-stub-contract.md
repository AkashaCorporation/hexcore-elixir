# MSVC CRT Init Stub Contract

## Context

MSVC-compiled PE binaries run `__scrt_common_main_seh` (or the equivalent entry thunk) before reaching `main()`. This entry thunk calls six Universal CRT functions that the PE loader must stub if the binary is to survive CRT init. Without these stubs, the binary crashes with `UC_ERR_READ_UNMAPPED` at roughly instruction 239 on a typical x64 MSVC binary, dereferencing NULL inside `__p___argv`.

This contract was derived empirically by tracing `Malware HexCore Defeat.exe` v3 "Ashaka Shadow" in the reference implementation on 2026-04-14.

## The 6 critical stubs

Each stub must be registered under **three DLL aliases** because the UCRT splits its surface across multiple DLL names:

```
api-ms-win-crt-runtime-l1-1-0.dll   ← API set alias
ucrtbase.dll                         ← concrete implementation DLL
msvcrt.dll                           ← legacy compatibility alias
```

If you only register one alias, the 2/3 of binaries that import the other name will still fault.

### Stub 1: `__p___argv`

**Signature**: `char*** __p___argv(void)`
**Behavior**: Returns a pointer to a `char**` (the argv array).
**Implementation**:
```
ensure_crt_data_allocated()
return crt_argv_ptr   // pointer to [&narrow_program_name, NULL]
```

### Stub 2: `__p___argc`

**Signature**: `int* __p___argc(void)`
**Behavior**: Returns a pointer to an int (argc).
**Implementation**:
```
ensure_crt_data_allocated()
// Write crt_argc_value (=1) to a slot inside the CRT data block.
// Return the address of that slot.
return crt_data_ptr + 0x58   // scratch int slot
```
(0x58 is the offset chosen in the reference implementation. Any unused 4-byte slot in the CRT data block works.)

### Stub 3: `_initterm`

**Signature**: `void _initterm(_PVFV* start, _PVFV* end)`
**Behavior (as documented)**: Walks a function-pointer table `[start..end)`, calling each non-NULL entry. Used for C++ static initializers.

**Behavior (Elixir stub)**: **No-op**. Return immediately. Log the slot count for diagnostics.

Rationale: real `_initterm` execution would require nested emulation, which Unicorn does not support reentrantly from a callback. For the malware corpus (`Malware HexCore Defeat.exe` v1/v2/v3 + MSVC Hello World), skipping static initializers does not break execution because the binaries' static initializers are empty or trivially side-effecting. If a future sample requires real walker execution, implement it via a stack-trampoline approach (push sentinel return address, redirect RIP to first initializer, hook the sentinel address).

```
Expected log: "[crt] _initterm(0x<start>, 0x<end>) skipped — N slots"
Return: 0
```

### Stub 4: `_initterm_e`

**Signature**: `int _initterm_e(_PIFV* start, _PIFV* end)`
**Behavior**: Same as `_initterm` but the callbacks return error codes. Return 0 on success.

**Implementation**: identical to `_initterm` stub. Return 0 (success).

### Stub 5: `_get_initial_narrow_environment`

**Signature**: `char*** _get_initial_narrow_environment(void)`
**Behavior**: Returns a pointer to the narrow (char-based) environment array.
**Implementation**:
```
ensure_crt_data_allocated()
return crt_environ_ptr   // pointer to [NULL] — empty env array
```

### Stub 6: `_get_initial_wide_environment`

**Signature**: `wchar_t*** _get_initial_wide_environment(void)`
**Behavior**: Same as narrow but for wide strings.
**Implementation**: Return `crt_wenviron_ptr`. Empty wide env array.

## The CRT data block (256 bytes)

`ensure_crt_data_allocated()` must allocate a 256-byte zero-filled block in the emulator heap on first call, then reuse it. The layout:

| Offset | Size | Content |
|---|---|---|
| 0x00 | 12 | `"malware.exe\0"` — narrow program name (ASCII) |
| 0x0C | 4 | padding (zero) |
| 0x10 | 8 | `&narrow_program_name` (i.e. `crt_data_ptr + 0x00`) |
| 0x18 | 8 | `NULL` — argv array terminator |
| 0x20 | 8 | `NULL` — environ array (empty, just a NULL terminator) |
| 0x28 | 24 | `L"malware.exe\0"` — wide program name (UTF-16LE, 12 code units) |
| 0x40 | 8 | `&wide_program_name` (i.e. `crt_data_ptr + 0x28`) |
| 0x48 | 8 | `NULL` — wargv array terminator |
| 0x50 | 8 | `NULL` — wenviron array terminator |
| 0x58 | 4 | `int argc = 1` (read by the `__p___argc` stub) |
| 0x5C | ... | unused scratch space |

The stub functions return pointers *into* this block:
- `crt_argv_ptr` = `crt_data_ptr + 0x10`
- `crt_environ_ptr` = `crt_data_ptr + 0x20`
- `crt_wargv_ptr` = `crt_data_ptr + 0x40`
- `crt_wenviron_ptr` = `crt_data_ptr + 0x50`

### Why this layout works

The CRT entry sequence is roughly:
```c
int argc = *__p___argc();                 // reads [crt_data+0x58] → 1
char** argv = *__p___argv();              // reads [crt_data+0x10] → crt_data+0x00 (pointer to "malware.exe")
char** envp = _get_initial_narrow_environment();  // returns crt_data+0x20
int ret = main(argc, argv, envp);
exit(ret);
```

Every dereference lands in the same 256-byte mapped block. `argv[0]` is a valid C string. `argv[1]` is NULL (proper terminator). `envp[0]` is NULL (proper empty environment). No fault.

## The CRT exit family

After `main()` returns, MSVC calls `exit(return_code)` → `_exit` → process termination. Elixir must intercept this so emulation stops cleanly instead of falling into garbage code.

Register these **15 handlers** (5 functions × 3 DLL aliases):

| Function | Behavior |
|---|---|
| `exit` | `emulator.stop()`, return 0 |
| `_exit` | same |
| `_Exit` | same |
| `quick_exit` | same |
| `abort` | same |

Without these, the reference implementation observed a 23,128-call infinite loop replaying fragments of `main()` until hitting the 1M instruction cap.

## Testing this contract

Phase 3 gate check: emulate a minimal MSVC Hello World binary.

```cpp
// hello.cpp — compile with: cl /EHsc hello.cpp
#include <cstdio>
int main(int argc, char** argv) {
    printf("argc=%d\n", argc);
    return 0;
}
```

Expected trace with Elixir's stubs:
1. `GetSystemTimeAsFileTime` → 0
2. `GetCurrentThreadId` → 0x1004
3. `GetCurrentProcessId` → 0x1000
4. `QueryPerformanceCounter` → 0x1
5. `_initterm_e` → 0 (no-op)
6. `_initterm` → 0 (no-op)
7. `_get_initial_narrow_environment` → `<env_ptr>`
8. `__p___argv` → `<argv_ptr>`
9. `__p___argc` → `<argc_ptr>`
10. `__stdio_common_vsprintf_s` or `WriteFile` (from printf)
11. `exit` → emulator stops

**Expected**: emulation terminates at the `exit()` call, total instructions 1,000–5,000. No crash. `stdout` (if captured) contains `"argc=1\n"`.

## Non-negotiable requirements

- All 6 stubs registered under **all 3 DLL aliases** (`api-ms-win-crt-runtime-l1-1-0.dll`, `ucrtbase.dll`, `msvcrt.dll`)
- `__p___argv` and `__p___argc` return **real, dereferenceable pointers** into mapped memory — not 0, not a sentinel
- `_initterm` returns successfully (0) **without walking the table**
- `ensure_crt_data_allocated` is idempotent — safe to call from any CRT stub entry
- The exit family calls `emulator.stop()` — otherwise emulation runs until the instruction cap

## Reference origin

This contract was discovered by tracing instruction-level crashes in `Malware HexCore Defeat.exe` v3 against the reference implementation (`hexcore-debugger/src/winApiHooks.ts`). The crash progression was:

1. **Pre-fix (instruction 239)**: `__p___argv` unstubbed → returned 0 → `mov rax, [0]` → NULL fault
2. **Post-stub-fix (instruction 398)**: `std::cout` data import returned the 0xC3 RET opcode as a pointer → `movsxd rcx, [0xc3+4]` → NULL fault (see `data-import-detection.md`)
3. **Post-data-import-fix (instruction 781)**: `PEB->Ldr` uninitialized → NULL fault in PEB walker (see `peb-ldr-data-layout.md`)
4. **Post-PEB-Ldr-fix (1M instructions, no crash)**: `exit()` stub returned instead of stopping → emulator looped to instruction cap

All four phases are captured in the specs in this directory. Implement all four or risk re-hitting the same progression.
