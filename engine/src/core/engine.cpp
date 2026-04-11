// HexCore Elixir — Core Engine
//
// Main emulation context. Owns the Unicorn engine handle,
// memory manager, and OS subsystem.

#include "elixir/elixir.h"
#include <memory>

struct ElixirContext {
    ElixirArch arch;
    ElixirOs   os;
    // TODO: uc_engine* uc;
    // TODO: std::unique_ptr<MemoryManager> mem;
    // TODO: std::unique_ptr<OsSubsystem> os_sub;
};

extern "C" {

ElixirContext* elixir_create(ElixirArch arch, ElixirOs os) {
    auto* ctx = new ElixirContext{};
    ctx->arch = arch;
    ctx->os   = os;
    // TODO: Initialize Unicorn engine for the given arch
    // TODO: Create OS subsystem
    return ctx;
}

void elixir_destroy(ElixirContext* ctx) {
    if (!ctx) return;
    // TODO: uc_close(ctx->uc);
    delete ctx;
}

ElixirError elixir_load(ElixirContext* ctx, const uint8_t* data, size_t len, uint64_t* out_entry) {
    if (!ctx || !data || len == 0) return ELIXIR_ERR_ARGS;
    // TODO: detect format, invoke loader, map sections
    (void)out_entry;
    return ELIXIR_ERR_LOADER; // stub
}

ElixirError elixir_run(ElixirContext* ctx, uint64_t start, uint64_t end, uint64_t max_insns) {
    if (!ctx) return ELIXIR_ERR_ARGS;
    // TODO: uc_emu_start(ctx->uc, start, end, 0, max_insns);
    (void)start; (void)end; (void)max_insns;
    return ELIXIR_ERR_UNICORN; // stub
}

ElixirError elixir_stop(ElixirContext* ctx) {
    if (!ctx) return ELIXIR_ERR_ARGS;
    // TODO: uc_emu_stop(ctx->uc);
    return ELIXIR_OK;
}

ElixirError elixir_mem_map(ElixirContext* ctx, uint64_t addr, uint64_t size, uint32_t prot) {
    if (!ctx) return ELIXIR_ERR_ARGS;
    (void)addr; (void)size; (void)prot;
    return ELIXIR_ERR_MEMORY; // stub
}

ElixirError elixir_mem_read(ElixirContext* ctx, uint64_t addr, uint8_t* buf, size_t len) {
    if (!ctx || !buf) return ELIXIR_ERR_ARGS;
    (void)addr; (void)len;
    return ELIXIR_ERR_MEMORY; // stub
}

ElixirError elixir_mem_write(ElixirContext* ctx, uint64_t addr, const uint8_t* buf, size_t len) {
    if (!ctx || !buf) return ELIXIR_ERR_ARGS;
    (void)addr; (void)len;
    return ELIXIR_ERR_MEMORY; // stub
}

ElixirError elixir_reg_read(ElixirContext* ctx, uint32_t reg_id, uint64_t* value) {
    if (!ctx || !value) return ELIXIR_ERR_ARGS;
    (void)reg_id;
    return ELIXIR_ERR_UNICORN; // stub
}

ElixirError elixir_reg_write(ElixirContext* ctx, uint32_t reg_id, uint64_t value) {
    if (!ctx) return ELIXIR_ERR_ARGS;
    (void)reg_id; (void)value;
    return ELIXIR_ERR_UNICORN; // stub
}

ElixirError elixir_snapshot_save(ElixirContext* ctx, uint8_t** out_data, size_t* out_len) {
    if (!ctx || !out_data || !out_len) return ELIXIR_ERR_ARGS;
    return ELIXIR_ERR_MEMORY; // stub
}

ElixirError elixir_snapshot_restore(ElixirContext* ctx, const uint8_t* data, size_t len) {
    if (!ctx || !data) return ELIXIR_ERR_ARGS;
    (void)len;
    return ELIXIR_ERR_MEMORY; // stub
}

void elixir_snapshot_free(uint8_t* data) {
    delete[] data;
}

} // extern "C"
