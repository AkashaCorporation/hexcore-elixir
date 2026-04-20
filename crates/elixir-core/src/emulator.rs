// elixir_core — Emulator
//
// The main emulation context. Manages CPU state, memory, and the execution loop.
// Delegates to the native C++ engine via FFI.

use crate::error::{ElixirError, ElixirResult};
use crate::ffi;
use crate::types::{Arch, MemProt, OsType, SimpleStopReason, StopReason};
use serde::Deserialize;

/// One Win32 API call captured by the engine's hook dispatcher.
/// Shape matches the JSON emitted by elixir_api_log_to_json.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiLogEntry {
    pub name: String,
    pub module: String,
    pub pc_address: u64,
    pub return_value: u64,
    pub arguments: Vec<u64>,
}

/// Configuration for creating an Elixir emulation session
#[derive(Debug, Clone)]
pub struct EmulatorConfig {
    pub arch: Arch,
    pub os: OsType,
    pub stack_size: u64,
    pub heap_size: u64,
    /// Enable permissive memory mapping (auto-map on fault)
    pub permissive_memory: bool,
}

impl Default for EmulatorConfig {
    fn default() -> Self {
        Self {
            arch: Arch::X86_64,
            os: OsType::Linux,
            stack_size: 2 * 1024 * 1024,   // 2 MB
            heap_size: 16 * 1024 * 1024,   // 16 MB
            permissive_memory: false,
        }
    }
}

/// The main emulation context
pub struct Emulator {
    pub config: EmulatorConfig,
    ctx: *mut ffi::ElixirContext,
}

// Safety: ElixirContext is thread-safe on the C++ side
unsafe impl Send for Emulator {}

impl Emulator {
    /// Create a new emulation context
    pub fn new(config: EmulatorConfig) -> ElixirResult<Self> {
        let arch = arch_to_ffi(config.arch);
        let os = os_to_ffi(config.os);

        let ctx = unsafe { ffi::elixir_create(arch, os) };

        if ctx.is_null() {
            return Err(ElixirError::Ffi(
                "Failed to create ElixirContext".to_string(),
            ));
        }

        Ok(Self { config, ctx })
    }

    /// Map a memory region
    pub fn mem_map(&mut self, addr: u64, size: u64, prot: MemProt) -> ElixirResult<()> {
        let result = unsafe { ffi::elixir_mem_map(self.ctx, addr, size, prot.bits()) };
        error_code_to_result(result)
    }

    /// Read memory from the emulator
    pub fn mem_read(&mut self, addr: u64, buf: &mut [u8]) -> ElixirResult<()> {
        let result = unsafe {
            ffi::elixir_mem_read(self.ctx, addr, buf.as_mut_ptr(), buf.len())
        };
        error_code_to_result(result)
    }

    /// Write memory to the emulator
    pub fn mem_write(&mut self, addr: u64, data: &[u8]) -> ElixirResult<()> {
        let result = unsafe {
            ffi::elixir_mem_write(self.ctx, addr, data.as_ptr(), data.len())
        };
        error_code_to_result(result)
    }

    /// Read a register value
    pub fn reg_read(&mut self, reg_id: u32) -> ElixirResult<u64> {
        let mut value: u64 = 0;
        let result = unsafe { ffi::elixir_reg_read(self.ctx, reg_id, &mut value) };
        error_code_to_result(result)?;
        Ok(value)
    }

    /// Write a register value
    pub fn reg_write(&mut self, reg_id: u32, value: u64) -> ElixirResult<()> {
        let result = unsafe { ffi::elixir_reg_write(self.ctx, reg_id, value) };
        error_code_to_result(result)
    }

    /// Load a binary into the emulator
    pub fn load(&mut self, data: &[u8]) -> ElixirResult<u64> {
        let mut entry_point: u64 = 0;
        let err = unsafe {
            ffi::elixir_load(
                self.ctx,
                data.as_ptr(),
                data.len(),
                &mut entry_point,
            )
        };
        match err {
            ffi::ElixirErrorCode::Ok => Ok(entry_point),
            _ => Err(error_code_to_error(err)),
        }
    }

    /// Start emulation from the given address
    pub fn run(&mut self, start: u64, end: u64, max_insns: u64) -> ElixirResult<StopReason> {
        let result = unsafe { ffi::elixir_run(self.ctx, start, end, max_insns) };

        match result {
            ffi::ElixirErrorCode::Ok => {
                // For Phase 1.1, assume we hit instruction limit
                // In future phases, we'll get actual stop reason from context
                Ok(StopReason::InstructionLimit(max_insns))
            }
            _ => Err(error_code_to_error(result)),
        }
    }

    /// Stop emulation
    pub fn stop(&mut self) -> ElixirResult<()> {
        let result = unsafe { ffi::elixir_stop(self.ctx) };
        error_code_to_result(result)
    }

    /// Get the stop reason from the last emulation run
    pub fn stop_reason(&self) -> SimpleStopReason {
        let r = unsafe { ffi::elixir_get_stop_reason(self.ctx) };
        match r {
            1 => SimpleStopReason::Exit,
            2 => SimpleStopReason::InsnLimit,
            3 => SimpleStopReason::Error,
            4 => SimpleStopReason::User,
            _ => SimpleStopReason::None,
        }
    }

    /// Set an engine option. Used for permissive_memory mode etc.
    pub fn set_option(&mut self, option: i32, value: u64) -> ElixirResult<()> {
        let err = unsafe { ffi::elixir_set_option(self.ctx, option, value) };
        error_code_to_result(err)
    }

    /// Enable or disable permissive memory mode (auto-map on fault).
    pub fn set_permissive_memory(&mut self, enabled: bool) -> ElixirResult<()> {
        self.set_option(1, if enabled { 1 } else { 0 }) // ELIXIR_OPT_PERMISSIVE_MEMORY = 1
    }

    /// Save a full snapshot of the emulation state
    pub fn snapshot_save(&self) -> ElixirResult<Vec<u8>> {
        let mut data_ptr: *mut u8 = std::ptr::null_mut();
        let mut data_len: usize = 0;
        let err = unsafe {
            ffi::elixir_snapshot_save(self.ctx, &mut data_ptr, &mut data_len)
        };
        error_code_to_result(err)?;
        if data_ptr.is_null() || data_len == 0 {
            return Err(ElixirError::Memory {
                addr: 0,
                reason: "Snapshot save returned empty data".into(),
            });
        }
        let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len).to_vec() };
        unsafe { ffi::elixir_snapshot_free(data_ptr) };
        Ok(data)
    }

    /// Restore from a snapshot
    pub fn snapshot_restore(&mut self, data: &[u8]) -> ElixirResult<()> {
        let err = unsafe {
            ffi::elixir_snapshot_restore(self.ctx, data.as_ptr(), data.len())
        };
        error_code_to_result(err)
    }

    /// Get the number of API calls logged
    pub fn api_log_count(&self) -> u64 {
        unsafe { ffi::elixir_api_log_count(self.ctx) }
    }

    /// Full detail of every API call captured since load.
    /// The engine allocates the JSON blob and we deserialise it once here;
    /// prefer this over api_log_count when downstream needs names/args/pc.
    pub fn api_log_snapshot(&self) -> ElixirResult<Vec<ApiLogEntry>> {
        let mut data_ptr: *mut u8 = std::ptr::null_mut();
        let mut data_len: usize = 0;
        let err = unsafe {
            ffi::elixir_api_log_to_json(self.ctx, &mut data_ptr, &mut data_len)
        };
        error_code_to_result(err)?;
        if data_ptr.is_null() || data_len == 0 {
            return Ok(Vec::new());
        }
        // Parse first, then free — the free is unconditional even on parse
        // error so the engine's heap doesn't leak when a caller ships a
        // malformed payload (shouldn't happen in practice).
        let parse_result: Result<Vec<ApiLogEntry>, _> = {
            let slice = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
            serde_json::from_slice(slice)
        };
        unsafe { ffi::elixir_snapshot_free(data_ptr) };
        parse_result.map_err(|e| ElixirError::Ffi(format!("api_log JSON parse: {}", e)))
    }

    // Interceptor
    pub fn interceptor_attach(&mut self, addr: u64) -> ElixirResult<()> {
        let err = unsafe { ffi::elixir_interceptor_attach(self.ctx, addr) };
        error_code_to_result(err)
    }

    pub fn interceptor_detach(&mut self, addr: u64) -> ElixirResult<()> {
        let err = unsafe { ffi::elixir_interceptor_detach(self.ctx, addr) };
        error_code_to_result(err)
    }

    pub fn interceptor_log_count(&self) -> u64 {
        unsafe { ffi::elixir_interceptor_log_count(self.ctx) }
    }

    // Stalker
    pub fn stalker_follow(&mut self) -> ElixirResult<()> {
        let err = unsafe { ffi::elixir_stalker_follow(self.ctx) };
        error_code_to_result(err)
    }

    pub fn stalker_unfollow(&mut self) -> ElixirResult<()> {
        let err = unsafe { ffi::elixir_stalker_unfollow(self.ctx) };
        error_code_to_result(err)
    }

    pub fn stalker_block_count(&self) -> u64 {
        unsafe { ffi::elixir_stalker_block_count(self.ctx) }
    }

    pub fn stalker_export_drcov(&self) -> ElixirResult<Vec<u8>> {
        let mut data_ptr: *mut u8 = std::ptr::null_mut();
        let mut data_len: usize = 0;
        let err = unsafe {
            ffi::elixir_stalker_export_drcov(self.ctx, &mut data_ptr, &mut data_len)
        };
        error_code_to_result(err)?;
        if data_ptr.is_null() || data_len == 0 {
            return Ok(Vec::new());
        }
        let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len).to_vec() };
        unsafe { ffi::elixir_snapshot_free(data_ptr) };  // Uses same free function (delete[])
        Ok(data)
    }

    /// Get the actual number of instructions executed in the last run
    pub fn instruction_count(&self) -> u64 {
        unsafe { ffi::elixir_get_instruction_count(self.ctx) }
    }
}

impl Drop for Emulator {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            unsafe {
                ffi::elixir_destroy(self.ctx);
            }
        }
    }
}

// Helper functions for type conversions

fn arch_to_ffi(arch: Arch) -> ffi::ElixirArch {
    match arch {
        Arch::X86 => ffi::ElixirArch::X86,
        Arch::X86_64 => ffi::ElixirArch::X86_64,
        Arch::Arm => ffi::ElixirArch::Arm,
        Arch::Arm64 => ffi::ElixirArch::Arm64,
    }
}

fn os_to_ffi(os: OsType) -> ffi::ElixirOs {
    match os {
        OsType::Linux => ffi::ElixirOs::Linux,
        OsType::Windows => ffi::ElixirOs::Windows,
        OsType::MacOS => ffi::ElixirOs::MacOS,
        OsType::Bare => ffi::ElixirOs::Bare,
    }
}

fn error_code_to_result(code: ffi::ElixirErrorCode) -> ElixirResult<()> {
    match code {
        ffi::ElixirErrorCode::Ok => Ok(()),
        _ => Err(error_code_to_error(code)),
    }
}

fn error_code_to_error(code: ffi::ElixirErrorCode) -> ElixirError {
    match code {
        ffi::ElixirErrorCode::Ok => ElixirError::Ffi("Unexpected success code".to_string()),
        ffi::ElixirErrorCode::Unicorn => ElixirError::Unicorn("Engine error".to_string()),
        ffi::ElixirErrorCode::Loader => ElixirError::Loader("Loader error".to_string()),
        ffi::ElixirErrorCode::Os => ElixirError::OsSubsystem("OS error".to_string()),
        ffi::ElixirErrorCode::Memory => ElixirError::Memory {
            addr: 0,
            reason: "Memory operation failed".to_string(),
        },
        ffi::ElixirErrorCode::Args => ElixirError::Ffi("Invalid arguments".to_string()),
        ffi::ElixirErrorCode::UcFault => ElixirError::Unicorn(
            "uc_emu_start faulted (SEH access violation inside libuc JIT); emulation aborted but process survived".to_string(),
        ),
    }
}
