// HexCore Elixir — Windows Process Environment Setup
//
// Clean-room implementation using:
//   - handoff/specs/peb-ldr-data-layout.md
//   - Microsoft TEB/PEB documentation (MSDN)
//
// Apache-2.0 licensed. No code copied verbatim.

#include "elixir/engine_internal.h"
#include <unicorn/x86.h>
#include <cstring>
#include <cstdio>

// Memory layout constants
constexpr uint64_t TEB_ADDRESS        = 0x7FFDE000;
constexpr uint64_t TEB_SIZE           = 0x2000;     // 8 KB
constexpr uint64_t PEB_ADDRESS        = 0x7FFD0000;
constexpr uint64_t PEB_SIZE           = 0x1000;     // 4 KB
constexpr uint64_t TLS_STORAGE_BASE   = 0x7FFB0000;
constexpr uint64_t TLS_VECTOR_ADDRESS = 0x7FFC0000;
constexpr uint64_t DEFAULT_STACK_BASE = 0x7FFF0000;
constexpr uint64_t DEFAULT_STACK_SIZE = 0x100000;   // 1 MB
constexpr uint64_t FAKE_PID           = 0x1000;
constexpr uint64_t FAKE_TID           = 0x1004;

ElixirError setup_windows_process_env(uc_engine* uc, MemoryManager* mem, 
                                       uint64_t image_base, uint64_t stack_base, 
                                       uint64_t stack_size) {
    if (!uc || !mem) return ELIXIR_ERR_ARGS;

    // A. Map stack region first (needed for RSP)
    ElixirError err = mem->map(stack_base, stack_size, UC_PROT_READ | UC_PROT_WRITE, "STACK");
    if (err != ELIXIR_OK) return err;

    // A. Map TEB and PEB pages
    err = mem->map(TEB_ADDRESS, TEB_SIZE, UC_PROT_READ | UC_PROT_WRITE, "TEB");
    if (err != ELIXIR_OK) return err;

    err = mem->map(PEB_ADDRESS, PEB_SIZE, UC_PROT_READ | UC_PROT_WRITE, "PEB");
    if (err != ELIXIR_OK) return err;

    // B. Write TEB64 fields
    // Zero-filled buffer for TEB
    uint8_t teb_data[TEB_SIZE];
    std::memset(teb_data, 0, TEB_SIZE);

    // TEB64 field offsets and values
    // Offset 0x08: StackBase (top of stack)
    *(uint64_t*)(teb_data + 0x08) = stack_base + stack_size;
    // Offset 0x10: StackLimit
    *(uint64_t*)(teb_data + 0x10) = stack_base;
    // Offset 0x30: Self pointer (TEB address)
    *(uint64_t*)(teb_data + 0x30) = TEB_ADDRESS;
    // Offset 0x40: ClientId.UniqueProcess (fake PID)
    *(uint64_t*)(teb_data + 0x40) = FAKE_PID;
    // Offset 0x48: ClientId.UniqueThread (fake TID)
    *(uint64_t*)(teb_data + 0x48) = FAKE_TID;
    // Offset 0x58: ThreadLocalStoragePointer
    *(uint64_t*)(teb_data + 0x58) = TLS_VECTOR_ADDRESS;
    // Offset 0x60: ProcessEnvironmentBlock (PEB address)
    *(uint64_t*)(teb_data + 0x60) = PEB_ADDRESS;

    // Write TEB to memory
    uc_err uc_err_code = uc_mem_write(uc, TEB_ADDRESS, teb_data, TEB_SIZE);
    if (uc_err_code != UC_ERR_OK) return ELIXIR_ERR_MEMORY;

    // C. Write PEB64 fields and PEB_LDR_DATA
    uint8_t peb_data[PEB_SIZE];
    std::memset(peb_data, 0, PEB_SIZE);

    // PEB64 field offsets
    // Offset 0x02: BeingDebugged = 0 (anti-anti-debug)
    peb_data[0x02] = 0;
    // Offset 0x10: ImageBaseAddress
    *(uint64_t*)(peb_data + 0x10) = image_base;
    // Offset 0x18: Ldr pointer (PEB_LDR_DATA at PEB + 0x200)
    *(uint64_t*)(peb_data + 0x18) = PEB_ADDRESS + 0x200;

    // D. Write PEB_LDR_DATA (at PEB_ADDRESS + 0x200)
    // The empty list trick - all LIST_ENTRY pairs point to themselves
    uint64_t ldr_base = PEB_ADDRESS + 0x200;

    // Offset 0x00: Length = 0x58
    *(uint32_t*)(peb_data + 0x200 + 0x00) = 0x58;
    // Offset 0x04: Initialized = 1
    peb_data[0x200 + 0x04] = 1;
    // Offset 0x08: SsHandle = 0 (already zero from memset)

    // InLoadOrderModuleList (offset 0x10) - self-referencing
    *(uint64_t*)(peb_data + 0x200 + 0x10) = ldr_base + 0x10;  // Flink
    *(uint64_t*)(peb_data + 0x200 + 0x18) = ldr_base + 0x10;  // Blink

    // InMemoryOrderModuleList (offset 0x20) - self-referencing
    *(uint64_t*)(peb_data + 0x200 + 0x20) = ldr_base + 0x20;  // Flink
    *(uint64_t*)(peb_data + 0x200 + 0x28) = ldr_base + 0x20;  // Blink

    // InInitializationOrderModuleList (offset 0x30) - self-referencing
    *(uint64_t*)(peb_data + 0x200 + 0x30) = ldr_base + 0x30;  // Flink
    *(uint64_t*)(peb_data + 0x200 + 0x38) = ldr_base + 0x30;  // Blink

    // Write PEB (including LDR_DATA at offset 0x200) to memory
    uc_err_code = uc_mem_write(uc, PEB_ADDRESS, peb_data, PEB_SIZE);
    if (uc_err_code != UC_ERR_OK) return ELIXIR_ERR_MEMORY;

    // E. Set GS base (IA32_GS_BASE MSR) for x64 TEB access via gs:[offset]
    uc_x86_msr msr_val;
    msr_val.rid = 0xC0000101;  // IA32_GS_BASE
    msr_val.value = TEB_ADDRESS;
    uc_err_code = uc_reg_write(uc, UC_X86_REG_MSR, &msr_val);
    if (uc_err_code != UC_ERR_OK) return ELIXIR_ERR_UNICORN;

    // F. Initialize RSP to top of stack (with shadow space alignment)
    // Stack grows down, so RSP starts at stack_base + stack_size
    // Subtract 0x28 to leave space for shadow space + alignment
    uint64_t stack_top = stack_base + stack_size - 0x28;
    uc_err_code = uc_reg_write(uc, UC_X86_REG_RSP, &stack_top);
    if (uc_err_code != UC_ERR_OK) return ELIXIR_ERR_UNICORN;

    return ELIXIR_OK;
}
