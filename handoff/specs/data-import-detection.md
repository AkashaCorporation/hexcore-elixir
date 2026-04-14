# C++ Data Import Detection and Handling

## The bug this prevents

PE loaders that treat every import as a function will write a single-byte `RET (0xC3)` stub into every IAT entry, then the binary crashes the moment it tries to use a **data import** like `std::cout`.

### Failure trace

MSVC C++ binaries that `#include <iostream>` import data exports from MSVCP140.dll:

```
?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A
?cerr@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A
?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@1@A
```

When the compiler emits `std::cout << "Hello\n"`, it generates something like:

```asm
lea rcx, [__imp_?cout@std@@...]      ; rcx = address of the IAT entry
mov rcx, [rcx]                        ; rcx = the cout object pointer (from IAT)
mov rdx, <string_literal>
call ??6?$basic_ostream@...@std@@@...

; Inside operator<<, first thing it does:
mov rax, [rcx]                        ; rax = vbtable pointer (virtual base table)
movsxd rcx, [rax+4]                   ; rcx = virtual base displacement (32-bit signed int)
mov rcx, [rcx+rsi+0x28]               ; rcx = the std::ios_base subobject
test rcx, rcx
jz handle_null
mov rax, [rcx]                        ; rax = vtable
call [rax+8]                          ; virtual call
```

If the IAT entry was a RET stub, `[iat] = 0x70000180` (stub address). Then `mov rax, [0x70000180]` reads the 8 bytes starting at the stub, which are `c3 00 00 00 00 00 00 00` — the literal machine code of the RET instruction. So `rax = 0xc3`. Then `[rax+4] = [0xc7]` faults in the NULL page.

This crash appears roughly 160 instructions after CRT init completes, as the first `std::cout << ...` chain runs in `main()`.

## The fix

The PE loader must **detect** C++ data imports by their mangled name and allocate a different kind of backing block for them: a **self-referential 4 KB data block** that survives the canonical MSVC vbtable dereference pattern.

### Detection: `is_data_import(mangled_name)`

MSVC C++ name mangling encodes the storage class as a single character right after the `@@` qualified-name terminator:

- `0-9` → data (static member, global, vtable, vbtable, typedef)
- `Y` → free function
- `Q` → public instance member function
- `U` → public virtual member function
- `V` → protected virtual member function
- ... (letters for functions)

**Regex (Rust or C++ equivalent)**:

```
^\?[A-Za-z_]\w*(?:@[A-Za-z_]\w*)+@@[0-9]
```

Breakdown:
- `^\?` — must start with `?` (MSVC mangling marker)
- `[A-Za-z_]\w*` — identifier name
- `(?:@[A-Za-z_]\w*)+` — at least one `@`-prefixed scope (e.g. `@std`)
- `@@` — qualified-name terminator
- `[0-9]` — storage class digit (data)

**Pre-filter**: reject anything starting with `??` — those are operator names (`??6` = `operator<<`, `??0` = constructor, etc.) and are **always functions**, not data.

### Test cases (verify your implementation with exactly these inputs)

| Input | Expected |
|---|---|
| `?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A` | ✅ data |
| `?cerr@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A` | ✅ data |
| `?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@1@A` | ✅ data |
| `?wcout@std@@3V?$basic_ostream@_WU?$char_traits@_W@std@@@1@A` | ✅ data |
| `?_Fac_tidy_reg@std@@3U_Fac_tidy_reg_t@1@A` | ✅ data |
| `?uncaught_exception@std@@YA_NXZ` | ❌ function (Y) |
| `??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@_J@Z` | ❌ function (?? prefix) |
| `?_Init@_Locinfo@std@@QEAA@XZ` | ❌ function (Q) |
| `CreateFileW` | ❌ not mangled |
| `IsDebuggerPresent` | ❌ not mangled |

**Minimum acceptance**: 10/10 of the above pass before Phase 2 lands.

### The data import block layout (4 KB)

For each detected data import, allocate a 4 KB zero-filled block in a dedicated memory region (the reference implementation uses `DATA_IMPORT_BASE = 0x71000000`, `DATA_IMPORT_SIZE = 8 MB`, `DATA_IMPORT_BLOCK_SIZE = 4 KB`). Patch the IAT entry with the address of this block.

Layout of each block:

| Offset | Size | Content |
|---|---|---|
| 0x000 | 8 | `self + 0x100` — pointer to the fake vbtable/vtable inside this same block |
| 0x008 | 0xF8 | zero-filled (real-looking data fields) |
| 0x100 | 0xF00 | zero-filled (the fake vtable/vbtable area) |

That's literally all. Write one pointer at offset 0, leave the rest as zeros.

### Why this survives the MSVC access pattern

Recall the crashing instruction sequence:

```asm
mov rax, [rcx]                ; 1
movsxd rcx, [rax+4]           ; 2
mov rcx, [rcx+rsi+0x28]       ; 3
test rcx, rcx                 ; 4
jz handle_null                ; 5
```

With `rcx = block_base` and `rsi` also equal to `block_base` (usual convention — the caller loads rcx and rsi to the same pointer before dispatching):

1. `rax = [rcx] = block_base + 0x100` — **valid mapped address** (still inside the 4 KB block)
2. `rcx = [rax+4] = [block_base + 0x104] = 0` — **readable, value 0**
3. `rcx = [0 + block_base + 0x28] = [block_base + 0x28] = 0` — **readable, value 0**
4. `test 0, 0` → ZF=1
5. `jz` taken — the **compiler-emitted null check** catches the fake object and skips the virtual call

MSVC always emits this null check before stream method dispatch because streams legitimately can be null (`std::cout` can fail). Our fake block hits the "null stream" path and gracefully no-ops.

## Integration with the PE import parser

```
for each ImportDescriptor in PE import directory:
    for each ThunkData:
        name = read_import_name(thunk)
        if is_data_import(name):
            backing = create_data_import_block()   // 4 KB, write self-pointer at 0
            data_import_map[backing] = import_entry
        else:
            backing = create_function_stub()       // 16 bytes, write 0xC3 at 0
            stub_map[backing] = import_entry
        patch_iat_entry(thunk_address, backing)
```

The two maps (`data_import_map` and `stub_map`) are tracked separately for diagnostics but are **not consulted during emulation** — the CODE hook on stub addresses handles function calls, and data imports are never hit by a CODE hook (the binary only dereferences them as data).

## Observed results

On `Malware HexCore Defeat.exe` v3 (MSVC PE64, 76 imports):

- Without fix: crash at instruction 398, `UC_ERR_READ_UNMAPPED` reading `0xc7`
- With fix: **781 instructions**, 3 complete `std::cout << X` chains observed (15 MSVCP140 vtable method calls: `good` → `setstate` → `uncaught_exception` → `_Osfx` → `operator<<`, repeated 3 times)

The 15 vtable calls demonstrate that the self-referential block works not just for the first dereference but for **chained virtual calls** through the fake vtable area.

## What's NOT handled by this spec

- **Vtable imports** (`??_7classname@@6B@` — vftable, `??_R0...` — RTTI) — the regex rejects them because they start with `??`. In practice no sample imports these directly (they're accessed indirectly via the cout/cerr objects whose vptr was already faked). If a future sample needs them, extend the detection to accept specific `??_<letter>` prefixes.
- **Non-std namespace data imports** — anything outside `std::`. The regex technically matches them as long as they end in `@@[0-9]`, but test coverage is std-focused.
- **Real `std::cout` behavior** — this spec does NOT make `printf` or `cout` produce output. It prevents crashes. If your Phase 3 plan includes observable stdout capture, route it through the `__stdio_common_vsprintf_s` stub or similar.

## Reference origin

This contract was discovered on 2026-04-14 while debugging why `Malware HexCore Defeat.exe` v3 crashed at instruction 398 inside the reference implementation. The crash instruction was:

```
48 63 48 04   movsxd rcx, dword ptr [rax+4]
```

with `rax = 0xc3`. Working backwards through `mov rax, [rcx]` revealed `rcx = 0x70000180`, which was enumerated as stub #24 of the PE imports and identified as `?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A` — std::cout.

Before this session, `peLoader.ts` had no detection for data imports and wrote a RET stub for every IAT entry. The fix added `isDataImport()` and `createDataImportBlock()` and preserved backwards compatibility for the 74 non-data imports on the same sample.
