# Win32 API Hook Contract — the 35 critical handlers

## Purpose

Elixir's `elixir_os/windows` must register hook handlers for at least these 35 Win32 APIs to pass the Parity Gate (G1–G4). Each handler fires when the emulator executes a CODE hook at a stub address that was patched into the IAT by the PE loader.

The dispatching architecture is simple:
1. PE loader writes a 16-byte `RET` stub at each function IAT entry
2. Elixir installs a CODE hook on the stub region (`STUB_BASE..STUB_BASE+STUB_SIZE`)
3. When the hook fires, it looks up the stub address → import entry → handler function
4. The handler reads arguments from registers (x64) or stack (x86), does its thing, writes the return value to `rax`/`eax`, and pops the return address

## Calling convention reminder (x64 Microsoft)

- Args 1–4: `rcx`, `rdx`, `r8`, `r9`
- Args 5+: stack at `[rsp+0x28]`, `[rsp+0x30]`, ...
- Return value: `rax`
- Caller cleans the stack (32-byte shadow space below `rsp` for args 1–4 spillage)
- Return address: `[rsp]` before the call, popped by `ret`

## Calling convention reminder (x86 stdcall, typical for Win32)

- All args on the stack, pushed right-to-left
- Return value: `eax`
- Callee cleans the stack (`ret N`)
- Return address: `[esp]` before the call

## The 35 handlers

For each handler, the spec format is:

```
Name: KernelModule!FunctionName
Args: (type arg1, type arg2, ...)
Return: what to put in rax/eax
Side effects: what memory/state changes
Rationale: why this exact stub behavior works for the corpus
```

### Process / thread identity (5 handlers)

```
kernel32!GetCurrentProcess
Args: none
Return: 0xFFFFFFFFFFFFFFFF (pseudo-handle, -1 as qword)
Side effects: none
Rationale: Windows uses -1 as the pseudo-handle for "current process"

kernel32!GetCurrentProcessId
Args: none
Return: 0x1000 (fake PID, any non-zero value works)
Side effects: none

kernel32!GetCurrentThread
Args: none
Return: 0xFFFFFFFFFFFFFFFE (-2 pseudo-handle)

kernel32!GetCurrentThreadId
Args: none
Return: 0x1004 (fake TID; keep consistent with TEB.ClientId.UniqueThread)

kernel32!ExitProcess
Args: (UINT ExitCode)
Return: doesn't return
Side effects: emulator.stop()
```

### Time (5 handlers — used by anti-emulation timing checks)

```
kernel32!GetTickCount
Args: none
Return: (tick_counter++) & 0xFFFFFFFF
Side effects: advance internal tick counter by ~10 ms
Rationale: anti-emulation checks call this twice and measure the delta. If both calls return the same value, the check fails. Advance monotonically.

kernel32!GetTickCount64
Args: none
Return: tick_counter (full 64-bit)
Side effects: advance counter

kernel32!QueryPerformanceCounter
Args: (LARGE_INTEGER* lpPerformanceCount)
Return: 1 (TRUE)
Side effects: write the current tick_counter into [lpPerformanceCount]
Rationale: anti-emulation rdtsc-style checks. Always advance.

kernel32!QueryPerformanceFrequency
Args: (LARGE_INTEGER* lpFrequency)
Return: 1 (TRUE)
Side effects: write 10000000 (10 MHz) into [lpFrequency]

kernel32!GetSystemTimeAsFileTime
Args: (FILETIME* lpSystemTimeAsFileTime)
Return: 0 (void function, return value ignored)
Side effects: write the current FILETIME (tick_counter in 100ns units) into [lpSystemTimeAsFileTime]

kernel32!Sleep
Args: (DWORD dwMilliseconds)
Return: 0 (void)
Side effects: advance tick_counter by dwMilliseconds × 10000 (FILETIME units)
Rationale: malware uses Sleep() as a retry delay. Returning instantly is fine; advancing the clock makes subsequent GetTickCount look coherent.
```

### IMPORTANT: the BigInt / uint64 trap

On x64 Unicorn, register values are 64-bit. When you read `Date.now()` or `time(NULL)` or any time source on the host, you get a signed 64-bit or a JS Number. **Coerce to unsigned 32-bit BEFORE storing**:

```rust
// Correct:
self.tick_counter = (host_time_ms as u64) & 0xFFFFFFFF;

// WRONG — would produce a negative value that turns into 0xFFFFFFFF00000000 when written to RAX:
self.tick_counter = host_time_ms as i64;
```

In TypeScript the reference implementation previously had:
```ts
this.tickCount = Date.now() & 0xFFFFFFFF; // BUG: & is signed int32, high bit flips sign
```
The fix was:
```ts
this.tickCount = (Date.now() & 0xFFFFFFFF) >>> 0; // unsigned coercion
```
Watch for this in whatever language you're implementing.

### Process / Module handles (4 handlers)

```
kernel32!GetModuleHandleA
Args: (LPCSTR lpModuleName)
Return:
  - If lpModuleName == NULL: image_base of the currently loaded PE
  - If lpModuleName is a string matching a known module: a fake handle
  - Otherwise: 0
Side effects: none

kernel32!GetModuleHandleW
Args: (LPCWSTR lpModuleName)
Return: same as GetModuleHandleA but reads UTF-16LE

kernel32!LoadLibraryA
Args: (LPCSTR lpLibFileName)
Return: a fake HMODULE (allocate a new stub handle; increment counter)
Side effects: track the load for subsequent GetProcAddress calls

kernel32!LoadLibraryW
Args: (LPCWSTR lpLibFileName)
Return: same as LoadLibraryA
```

### GetProcAddress — the critical one

```
kernel32!GetProcAddress
Args: (HMODULE hModule, LPCSTR lpProcName)
Return:
  - If lpProcName is a string: look up the function in the import table of hModule; return the stub address
  - If lpProcName is an ordinal (high 16 bits zero, low 16 bits non-zero): look up by ordinal
  - If not found: 0
Side effects: if the function wasn't in the static import table (malware looking up runtime APIs), lazily create a new stub, register a handler, and return the stub address
Rationale: the v3 malware uses GetProcAddress + LoadLibrary fallback for non-hashed APIs. Must return real stub addresses that subsequent CODE hooks can intercept.
```

### Memory (6 handlers)

```
kernel32!VirtualAlloc
Args: (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
Return: address of newly mapped page (heap-allocated), or the hinted address if non-zero
Side effects: uc_mem_map the new region with appropriate permissions

kernel32!VirtualFree
Args: (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
Return: 1 (TRUE)
Side effects: uc_mem_unmap

kernel32!VirtualProtect
Args: (LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
Return: 1 (TRUE)
Side effects: uc_mem_protect, write old protection flags into [lpflOldProtect]

kernel32!HeapCreate
Args: (DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
Return: fake heap handle (allocate from heap allocator)

kernel32!HeapAlloc
Args: (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
Return: newly allocated address (delegates to memory manager)
Side effects: memory mapped + zero-filled if HEAP_ZERO_MEMORY bit set

kernel32!HeapFree
Args: (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
Return: 1 (TRUE)
Side effects: memory manager marks block as free

kernel32!GetProcessHeap
Args: none
Return: a fixed fake handle (e.g. 0xDEADBEEF)
```

### File I/O (5 handlers — route through VFS)

```
kernel32!CreateFileA / CreateFileW
Args: (LPCSTR/LPCWSTR lpFileName, DWORD dwDesiredAccess, ..., ..., DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
Return: a VFS handle (wrap in a fake HANDLE), or INVALID_HANDLE_VALUE (-1) on failure
Side effects: open the VFS node matching lpFileName

kernel32!ReadFile
Args: (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
Return: 1 (TRUE) on success, 0 on failure
Side effects: read from VFS, write into [lpBuffer], write actual count into [lpNumberOfBytesRead]

kernel32!WriteFile
Args: (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
Return: 1 (TRUE)
Side effects: write to VFS (or capture to stdout buffer if hFile == stdout pseudo-handle)

kernel32!CloseHandle
Args: (HANDLE hObject)
Return: 1 (TRUE)
Side effects: close VFS node or release fake handle
```

### Debug detection (critical for the v3 malware)

```
kernel32!IsDebuggerPresent
Args: none
Return: 0 (FALSE)
Rationale: tell the malware we're not a debugger. Matches PEB.BeingDebugged=0.

kernel32!CheckRemoteDebuggerPresent
Args: (HANDLE hProcess, PBOOL pbDebuggerPresent)
Return: 1 (TRUE)
Side effects: write 0 (FALSE) into [pbDebuggerPresent]

kernel32!OutputDebugStringA / OutputDebugStringW
Args: (LPCSTR/LPCWSTR lpOutputString)
Return: 0 (void)
Side effects: log the string for Elixir diagnostics, but return without calling the debugger
```

### Anti-VM hostname/registry detection (critical for v3)

```
kernel32!GetComputerNameA
Args: (LPSTR lpBuffer, LPDWORD nSize)
Return: 1 (TRUE)
Side effects: write a non-VM-looking name into [lpBuffer] (e.g. "DESKTOP-USER01\0"), update [nSize]
Rationale: anti-VM check compares against "VMWARE", "VBOX", etc. Return something that does NOT match those strings.

kernel32!GetComputerNameW
Same as A but UTF-16LE.

advapi32!RegOpenKeyExA / RegOpenKeyExW
Args: (HKEY hKey, LPCSTR/LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
Return:
  - If lpSubKey is in the anti-VM list (SOFTWARE\VirtualBox*, SOFTWARE\VMware*, etc.): ERROR_FILE_NOT_FOUND (2)
  - Otherwise: ERROR_SUCCESS (0) and write a fake HKEY into [phkResult]
Side effects: the registry failure for VM-related keys is what makes the anti-VM check conclude "not a VM"

advapi32!RegQueryValueExA / RegQueryValueExW
Similar: return empty / ERROR_FILE_NOT_FOUND for anti-VM queries

advapi32!RegCloseKey
Args: (HKEY hKey)
Return: 0 (ERROR_SUCCESS)
```

### String / locale (needed by printf and friends)

```
kernel32!WideCharToMultiByte
Args: (UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, ...)
Return: number of bytes written (or required, if lpMultiByteStr == NULL)
Side effects: simple ASCII-range conversion (not a full ICU; UTF-16 chars 0x00..0x7F pass through, others become '?')

kernel32!MultiByteToWideChar
Similar, reverse direction

api-ms-win-crt-stdio-l1-1-0.dll!__stdio_common_vsprintf_s
Args: (unsigned __int64 _Options, char* _Buffer, size_t _BufferCount, const char* _Format, _locale_t _Locale, va_list _ArgList)
Return: number of chars written, or -1 on error
Side effects: simplified printf-family format implementation. Supports %s %d %x %u %p. Writes result into [_Buffer].
```

## Handler dispatch mechanism

The reference implementation uses a `Map<stub_address, handler>` lookup. For Elixir:

```rust
enum ApiHandler {
    Static(fn(&mut Emulator, &[u64]) -> u64),
    // ... potentially dynamic for LoadLibrary'd functions
}

struct Win32HookTable {
    handlers: HashMap<u64, ApiHandler>,
    stub_to_import: HashMap<u64, ImportEntry>,
}

impl Win32HookTable {
    fn register(&mut self, dll: &str, name: &str, handler: fn(&mut Emulator, &[u64]) -> u64) {
        for alias in dll_aliases(dll) {
            // e.g. "api-ms-win-crt-runtime-l1-1-0.dll", "ucrtbase.dll", "msvcrt.dll"
            // all map to the same handler
        }
    }
    
    fn dispatch(&mut self, emu: &mut Emulator, stub_addr: u64) {
        let args = read_args(emu, 8); // x64: rcx, rdx, r8, r9, [rsp+0x28..]
        let result = match self.handlers.get(&stub_addr) {
            Some(handler) => handler(emu, &args),
            None => 0,
        };
        emu.set_rax(result);
        // Pop return address from [rsp] and set rip to it, increment rsp by 8
        let ret_addr = emu.read_u64(emu.rsp())?;
        emu.set_rip(ret_addr);
        emu.set_rsp(emu.rsp() + 8);
    }
}
```

## DLL alias table

Every handler registration must cover **every** DLL alias the API might be imported under:

```
kernel32 / kernel32.dll / kernelbase.dll / api-ms-win-core-*.dll
ntdll / ntdll.dll
advapi32 / advapi32.dll / api-ms-win-security-*.dll
user32 / user32.dll
api-ms-win-crt-runtime-l1-1-0.dll / ucrtbase.dll / msvcrt.dll
api-ms-win-crt-stdio-l1-1-0.dll / ucrtbase.dll / msvcrt.dll
api-ms-win-crt-string-l1-1-0.dll / ucrtbase.dll / msvcrt.dll
api-ms-win-crt-heap-l1-1-0.dll / ucrtbase.dll / msvcrt.dll
psapi / psapi.dll / api-ms-win-core-psapi-*.dll
wininet / wininet.dll
ws2_32 / ws2_32.dll
shell32 / shell32.dll
```

## Reference origin

Extracted from `extensions/hexcore-debugger/src/winApiHooks.ts` (the reference implementation, ~1100 lines of TypeScript) on 2026-04-14. The handler list was curated based on which APIs actually fire during emulation of the malware corpus — the reference ships ~35 handlers and that's enough to run `Malware HexCore Defeat.exe` v1/v2/v3 + a minimal MSVC Hello World to completion.

For the CRT-specific handlers (`__p___argv`, `__p___argc`, `_initterm`, `_initterm_e`, `_get_initial_narrow_environment`, `_get_initial_wide_environment`, `exit`, `_exit`, `_Exit`, `quick_exit`, `abort`) see the companion spec `msvc-crt-stub-contract.md`.
