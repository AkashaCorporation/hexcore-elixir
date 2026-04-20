// HexCore Elixir — Engine Internal Header
//
// Internal structures and function declarations shared between
// engine core and loader implementations.
//
// Apache-2.0 licensed. No code copied verbatim.

#pragma once

// Disable Windows min/max macros globally before any includes
#if defined(_WIN32)
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
#endif

#include "elixir/elixir.h"
#include "elixir/memory_manager.h"
#include "elixir/win32_hooks.h"
#include "elixir/interceptor.h"
#include "elixir/stalker.h"
#include "elixir/linux_syscalls.h"
#include "elixir/linux_stubs.h"
#include <unicorn/unicorn.h>
#include <memory>
#include <vector>
#include <string>

// Import entry for API hook registration
struct ImportEntry {
    std::string dll_name;
    std::string func_name;
    uint64_t stub_addr;
    bool is_data_import;
};

// Internal context structure (opaque to public API)
struct ElixirContext {
    ElixirArch arch;
    ElixirOs   os;
    uc_engine* uc = nullptr;
    std::unique_ptr<MemoryManager> mem;
    std::vector<ImportEntry> imports;
    std::unique_ptr<Win32HookTable> win32_hooks;
    std::unique_ptr<Interceptor> interceptor;
    std::unique_ptr<Stalker> stalker;
    std::unique_ptr<LinuxSyscallHandler> linux_syscalls;
    std::unique_ptr<LinuxKernelStubs> linux_stubs;
    uint64_t image_base = 0;  // Actual image base from PE/ELF header
    ElixirStopReason stop_reason = ELIXIR_STOP_NONE;
    uint64_t instruction_count = 0;  // Actual instructions executed
    // Set to true when elixir_run's SEH barrier catches a fault inside
    // uc_emu_start. After this, the engine is assumed unusable: any
    // further uc_* call may re-fault inside the corrupted libuc state,
    // so the public API short-circuits and returns ELIXIR_ERR_UC_FAULT
    // until the caller disposes the Emulator.
    bool tainted = false;
};

// Loader function declarations
ElixirError pe_load(ElixirContext* ctx, const uint8_t* data, uint64_t len, uint64_t* entry_point, std::vector<ImportEntry>* out_imports = nullptr, uint64_t* out_image_base = nullptr);
ElixirError elf_load(ElixirContext* ctx, const uint8_t* data, uint64_t len, uint64_t* entry_point);
ElixirError macho_load(ElixirContext* ctx, const uint8_t* data, uint64_t len, uint64_t* entry_point);

// Format detection
enum class BinaryFormat {
    PE,
    ELF,
    MachO,
    Raw,
    Unknown
};

BinaryFormat detect_format(const uint8_t* data, uint64_t len);

// Windows process environment setup
ElixirError setup_windows_process_env(uc_engine* uc, MemoryManager* mem,
                                       uint64_t image_base, uint64_t stack_base,
                                       uint64_t stack_size);
