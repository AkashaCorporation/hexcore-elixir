// HexCore Elixir — Mach-O Loader
//
// Parses Mach-O (macOS, iOS).
// Lower priority — stub for now.
//
// Reference: Apple Mach-O Programming Topics
//
// Apache-2.0 licensed. No code copied verbatim.

#include "elixir/engine_internal.h"

ElixirError macho_load(ElixirContext* ctx, const uint8_t* data, uint64_t len, uint64_t* entry_point) {
    // Stub: Mach-O loader not yet implemented
    (void)ctx;
    (void)data;
    (void)len;
    (void)entry_point;
    return ELIXIR_ERR_LOADER;
}
