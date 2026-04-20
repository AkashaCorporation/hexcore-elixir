// HexCore Elixir — FFI Declarations
//
// Clean-room implementation binding to:
//   - HexCore Elixir C API (elixir/elixir.h)
//
// Apache-2.0 licensed. No code copied verbatim.

// Opaque handle — matches C++ ElixirContext
#[repr(C)]
pub struct ElixirContext {
    _private: [u8; 0],
}

// Architecture enum — must match C enum ElixirArch
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElixirArch {
    X86 = 0,
    X86_64 = 1,
    Arm = 2,
    Arm64 = 3,
}

// OS enum — must match C enum ElixirOs
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElixirOs {
    Linux = 0,
    Windows = 1,
    MacOS = 2,
    Bare = 3,
}

// Error enum — must match C enum ElixirError
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElixirErrorCode {
    Ok = 0,
    Unicorn = -1,
    Loader = -2,
    Os = -3,
    Memory = -4,
    Args = -5,
    // SEH caught inside uc_emu_start — libuc's JIT faulted, we survived.
    UcFault = -6,
}

extern "C" {
    pub fn elixir_create(arch: ElixirArch, os: ElixirOs) -> *mut ElixirContext;
    pub fn elixir_destroy(ctx: *mut ElixirContext);

    pub fn elixir_load(
        ctx: *mut ElixirContext,
        data: *const u8,
        len: usize,
        out_entry: *mut u64,
    ) -> ElixirErrorCode;

    pub fn elixir_run(
        ctx: *mut ElixirContext,
        start: u64,
        end: u64,
        max_insns: u64,
    ) -> ElixirErrorCode;
    pub fn elixir_stop(ctx: *mut ElixirContext) -> ElixirErrorCode;
    pub fn elixir_get_stop_reason(ctx: *mut ElixirContext) -> i32;

    pub fn elixir_set_option(
        ctx: *mut ElixirContext,
        option: i32,
        value: u64,
    ) -> ElixirErrorCode;

    pub fn elixir_mem_map(
        ctx: *mut ElixirContext,
        addr: u64,
        size: u64,
        prot: u32,
    ) -> ElixirErrorCode;
    pub fn elixir_mem_read(
        ctx: *mut ElixirContext,
        addr: u64,
        buf: *mut u8,
        len: usize,
    ) -> ElixirErrorCode;
    pub fn elixir_mem_write(
        ctx: *mut ElixirContext,
        addr: u64,
        buf: *const u8,
        len: usize,
    ) -> ElixirErrorCode;

    pub fn elixir_reg_read(
        ctx: *mut ElixirContext,
        reg_id: u32,
        value: *mut u64,
    ) -> ElixirErrorCode;
    pub fn elixir_reg_write(
        ctx: *mut ElixirContext,
        reg_id: u32,
        value: u64,
    ) -> ElixirErrorCode;

    pub fn elixir_snapshot_save(
        ctx: *mut ElixirContext,
        out_data: *mut *mut u8,
        out_len: *mut usize,
    ) -> ElixirErrorCode;
    pub fn elixir_snapshot_restore(
        ctx: *mut ElixirContext,
        data: *const u8,
        len: usize,
    ) -> ElixirErrorCode;
    pub fn elixir_snapshot_free(data: *mut u8);

    pub fn elixir_api_log_count(ctx: *mut ElixirContext) -> u64;

    // Serialises the Win32 api_log to a JSON array (UTF-8).
    // *out_data is owned by the engine and must be released via
    // elixir_snapshot_free (same new[]/delete[] pair as snapshots).
    pub fn elixir_api_log_to_json(
        ctx: *mut ElixirContext,
        out_data: *mut *mut u8,
        out_len: *mut usize,
    ) -> ElixirErrorCode;

    // Interceptor
    pub fn elixir_interceptor_attach(ctx: *mut ElixirContext, addr: u64) -> ElixirErrorCode;
    pub fn elixir_interceptor_detach(ctx: *mut ElixirContext, addr: u64) -> ElixirErrorCode;
    pub fn elixir_interceptor_log_count(ctx: *mut ElixirContext) -> u64;

    // Stalker
    pub fn elixir_stalker_follow(ctx: *mut ElixirContext) -> ElixirErrorCode;
    pub fn elixir_stalker_unfollow(ctx: *mut ElixirContext) -> ElixirErrorCode;
    pub fn elixir_stalker_block_count(ctx: *mut ElixirContext) -> u64;
    pub fn elixir_stalker_export_drcov(
        ctx: *mut ElixirContext,
        out_data: *mut *mut u8,
        out_len: *mut usize,
    ) -> ElixirErrorCode;

    // Instruction Count
    pub fn elixir_get_instruction_count(ctx: *mut ElixirContext) -> u64;
}
