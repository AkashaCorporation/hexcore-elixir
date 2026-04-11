// FFI boundary to the C++23 engine
//
// When the engine library is linked, these externs call into the C++ side.
// Until then, the Rust-only stubs in emulator.rs provide a pure-Rust fallback
// that drives HexCore-Unicorn directly via its N-API bindings.
//
// The C++ engine is optional — Elixir can run in "Rust-only" mode where the
// NAPI bridge talks to HexCore-Unicorn's existing Node addon. The C++ engine
// adds performance (JIT block cache, zero-copy memory) for production use.

// Placeholder — will be populated when engine/ is built
// extern "C" {
//     pub fn elixir_engine_create(arch: u32, os: u32) -> *mut std::ffi::c_void;
//     pub fn elixir_engine_destroy(ctx: *mut std::ffi::c_void);
//     pub fn elixir_engine_load(ctx: *mut std::ffi::c_void, data: *const u8, len: usize) -> i32;
//     pub fn elixir_engine_run(ctx: *mut std::ffi::c_void, start: u64, end: u64, count: u64) -> i32;
//     pub fn elixir_engine_stop(ctx: *mut std::ffi::c_void) -> i32;
//     pub fn elixir_engine_snapshot_save(ctx: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
//     pub fn elixir_engine_snapshot_restore(ctx: *mut std::ffi::c_void, snap: *mut std::ffi::c_void) -> i32;
// }
