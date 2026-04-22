// HexCore Elixir — C++23 Engine Public Header
//
// This is the C API exported by the engine static library.
// The Rust FFI layer (elixir-core/src/ffi.rs) calls these functions.

#pragma once

#include <cstdint>
#include <cstddef>

// Export macro for shared/static library
#ifdef _WIN32
  #ifdef ELIXIR_BUILDING_DLL
    #define ELIXIR_EXPORT __declspec(dllexport)
  #else
    #define ELIXIR_EXPORT
  #endif
#else
  #define ELIXIR_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

// --- Opaque handle ---
typedef struct ElixirContext ElixirContext;

// --- Arch / OS enums (must match Rust types.rs) ---
enum ElixirArch : uint32_t {
    ELIXIR_ARCH_X86     = 0,
    ELIXIR_ARCH_X86_64  = 1,
    ELIXIR_ARCH_ARM     = 2,
    ELIXIR_ARCH_ARM64   = 3,
};

enum ElixirOs : uint32_t {
    ELIXIR_OS_LINUX     = 0,
    ELIXIR_OS_WINDOWS   = 1,
    ELIXIR_OS_MACOS     = 2,
    ELIXIR_OS_BARE      = 3,
};

enum ElixirError : int32_t {
    ELIXIR_OK           =  0,
    ELIXIR_ERR_UNICORN  = -1,
    ELIXIR_ERR_LOADER   = -2,
    ELIXIR_ERR_OS       = -3,
    ELIXIR_ERR_MEMORY   = -4,
    ELIXIR_ERR_ARGS     = -5,
    // Windows Structured Exception (access violation etc.) caught inside
    // uc_emu_start — libuc's JIT code faulted and our __try/__except
    // handler recovered. The emulation is aborted but the process survives.
    ELIXIR_ERR_UC_FAULT = -6,
};

// --- Stop Reason ---
enum ElixirStopReason : int32_t {
    ELIXIR_STOP_NONE       = 0,
    ELIXIR_STOP_EXIT       = 1,  // exit()/ExitProcess() called
    ELIXIR_STOP_INSN_LIMIT = 2,  // hit max_insns
    ELIXIR_STOP_ERROR      = 3,  // UC_ERR_*
    ELIXIR_STOP_USER       = 4,  // elixir_stop() called
    ELIXIR_STOP_BREAKPOINT = 5,  // Project Pythia Oracle Hook breakpoint reached
};

// --- Lifecycle ---
ElixirContext* elixir_create(ElixirArch arch, ElixirOs os);
void           elixir_destroy(ElixirContext* ctx);

// --- Loading ---
ElixirError elixir_load(ElixirContext* ctx, const uint8_t* data, size_t len, uint64_t* out_entry);

// --- Execution ---
ElixirError elixir_run(ElixirContext* ctx, uint64_t start, uint64_t end, uint64_t max_insns);
ElixirError elixir_stop(ElixirContext* ctx);
ELIXIR_EXPORT ElixirStopReason elixir_get_stop_reason(ElixirContext* ctx);

// --- Options ---
#define ELIXIR_OPT_PERMISSIVE_MEMORY 1

ELIXIR_EXPORT ElixirError elixir_set_option(ElixirContext* ctx, int option, uint64_t value);

// --- Memory ---
ElixirError elixir_mem_map(ElixirContext* ctx, uint64_t addr, uint64_t size, uint32_t prot);
ElixirError elixir_mem_read(ElixirContext* ctx, uint64_t addr, uint8_t* buf, size_t len);
ElixirError elixir_mem_write(ElixirContext* ctx, uint64_t addr, const uint8_t* buf, size_t len);

// --- Registers ---
ElixirError elixir_reg_read(ElixirContext* ctx, uint32_t reg_id, uint64_t* value);
ElixirError elixir_reg_write(ElixirContext* ctx, uint32_t reg_id, uint64_t value);

// --- Snapshots ---
ElixirError elixir_snapshot_save(ElixirContext* ctx, uint8_t** out_data, size_t* out_len);
ElixirError elixir_snapshot_restore(ElixirContext* ctx, const uint8_t* data, size_t len);
void        elixir_snapshot_free(uint8_t* data);

// --- API Hook Logging ---
ELIXIR_EXPORT uint64_t elixir_api_log_count(ElixirContext* ctx);

// Serialise the Win32 api_log as a JSON array. Each entry is an object:
//   { "name": str, "module": str, "pc_address": u64,
//     "arguments": [u64 ...], "return_value": u64 }
// Caller must release *out_data via elixir_snapshot_free (same new[]/delete[]
// scheme as elixir_snapshot_save). On error *out_data is left untouched.
ELIXIR_EXPORT ElixirError elixir_api_log_to_json(ElixirContext* ctx,
                                                  uint8_t** out_data,
                                                  size_t* out_len);

// --- Interceptor ---
ELIXIR_EXPORT ElixirError elixir_interceptor_attach(ElixirContext* ctx, uint64_t addr);
ELIXIR_EXPORT ElixirError elixir_interceptor_detach(ElixirContext* ctx, uint64_t addr);
ELIXIR_EXPORT uint64_t elixir_interceptor_log_count(ElixirContext* ctx);

// --- Instruction Count ---
ELIXIR_EXPORT uint64_t elixir_get_instruction_count(ElixirContext* ctx);

// --- Breakpoints (Project Pythia Oracle Hook, v3.9.0-preview.oracle) ---
// Adds or removes a PC at which elixir_run will stop. Internally backed by a
// single persistent UC_HOOK_CODE that checks an unordered_set on every
// instruction boundary. When PC matches an entry, uc_emu_stop() is called
// and stop_reason is set to ELIXIR_STOP_BREAKPOINT. Breakpoints persist
// across elixir_run invocations and across snapshot save/restore — remove
// them with elixir_breakpoint_del before the session is over, or
// elixir_breakpoint_clear for a bulk wipe.
ELIXIR_EXPORT ElixirError elixir_breakpoint_add(ElixirContext* ctx, uint64_t addr);
ELIXIR_EXPORT ElixirError elixir_breakpoint_del(ElixirContext* ctx, uint64_t addr);
ELIXIR_EXPORT ElixirError elixir_breakpoint_clear(ElixirContext* ctx);

// --- Stalker ---
ELIXIR_EXPORT ElixirError elixir_stalker_follow(ElixirContext* ctx);
ELIXIR_EXPORT ElixirError elixir_stalker_unfollow(ElixirContext* ctx);
ELIXIR_EXPORT uint64_t elixir_stalker_block_count(ElixirContext* ctx);
ELIXIR_EXPORT ElixirError elixir_stalker_export_drcov(ElixirContext* ctx, uint8_t** out_data, size_t* out_len);

#ifdef __cplusplus
}
#endif
