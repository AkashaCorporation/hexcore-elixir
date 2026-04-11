// HexCore Elixir — C++23 Engine Public Header
//
// This is the C API exported by the engine static library.
// The Rust FFI layer (elixir-core/src/ffi.rs) calls these functions.

#pragma once

#include <cstdint>
#include <cstddef>

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
};

// --- Lifecycle ---
ElixirContext* elixir_create(ElixirArch arch, ElixirOs os);
void           elixir_destroy(ElixirContext* ctx);

// --- Loading ---
ElixirError elixir_load(ElixirContext* ctx, const uint8_t* data, size_t len, uint64_t* out_entry);

// --- Execution ---
ElixirError elixir_run(ElixirContext* ctx, uint64_t start, uint64_t end, uint64_t max_insns);
ElixirError elixir_stop(ElixirContext* ctx);

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

#ifdef __cplusplus
}
#endif
