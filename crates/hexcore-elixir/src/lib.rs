// HexCore Elixir — NAPI-RS Bridge
//
// This crate exposes the Elixir emulation engine to Node.js / VS Code
// via NAPI-RS, following the same pattern as @hexcore/helix.

use napi::bindgen_prelude::*;
use napi_derive::napi;

// ─── Version ────────────────────────────────────────────────────────────────

#[napi]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ─── JS Object Types (for interop) ───────────────────────────────────────────

/// Configuration for creating an Emulator instance.
#[napi(object)]
pub struct JsEmulatorConfig {
    /// Target architecture: "x86_64", "x86", "arm", "arm64"
    pub arch: String,
    /// Target OS: "linux", "windows", "macos", "bare"
    pub os: Option<String>,
    /// Maximum instructions for run() (0 = unlimited, use with caution)
    pub max_instructions: Option<i64>,
    /// Stack size in bytes (default: 2MB)
    pub stack_size: Option<i64>,
    /// Heap size in bytes (default: 16MB)
    pub heap_size: Option<i64>,
    /// Enable permissive memory mode (auto-map on fault)
    pub permissive_memory: Option<bool>,
    /// Enable verbose logging
    pub verbose: Option<bool>,
}

/// Result of a run() operation.
#[napi(object)]
pub struct JsStopReason {
    /// Stop reason kind: "exit", "insn_limit", "error", "user", "breakpoint", "none"
    pub kind: String,
    /// Current instruction pointer address
    pub address: BigInt,
    /// Number of instructions executed
    pub instructions_executed: i64,
    /// Error message (if any)
    pub message: String,
}

/// A single API call record.
#[napi(object)]
pub struct JsApiCall {
    /// API/function name
    pub name: String,
    /// Call address
    pub address: BigInt,
    /// Return value (0 if not available)
    pub return_value: BigInt,
}

/// A single Stalker basic block event.
#[napi(object)]
pub struct JsStalkerEvent {
    /// Block start address
    pub from: BigInt,
    /// Block end address
    pub to: BigInt,
    /// Execution count
    pub count: i64,
}

// ─── Emulator Class ──────────────────────────────────────────────────────────

/// The Elixir emulation engine.
///
/// Usage from TypeScript:
/// ```typescript
/// import { Emulator } from '@hexcore/elixir';
///
/// const emu = new Emulator({ arch: 'x86_64', max_instructions: 100000 });
/// const entry = emu.load(binaryBuffer);
/// const result = emu.run(entry, 0n);
/// console.log(result.kind); // 'exit', 'insn_limit', 'error', 'user'
/// emu.dispose();
/// ```
#[napi]
pub struct Emulator {
    inner: Option<elixir_core::emulator::Emulator>,
    disposed: bool,
    max_instructions: u64,
    verbose: bool,
}

#[napi]
impl Emulator {
    /// Create a new Emulator instance.
    #[napi(constructor)]
    pub fn new(config: JsEmulatorConfig) -> Result<Self> {
        let arch = parse_arch(&config.arch)?;
        let os = config
            .os
            .as_deref()
            .map(parse_os)
            .transpose()?
            .unwrap_or(elixir_core::types::OsType::Windows); // Default to Windows for PE binaries

        let core_config = elixir_core::emulator::EmulatorConfig {
            arch,
            os,
            stack_size: config.stack_size.map(|s| s as u64).unwrap_or(2 * 1024 * 1024),
            heap_size: config.heap_size.map(|h| h as u64).unwrap_or(16 * 1024 * 1024),
            permissive_memory: config.permissive_memory.unwrap_or(true), // Default to true for better compatibility
        };

        let mut emulator = elixir_core::emulator::Emulator::new(core_config)
            .map_err(|e| Error::from_reason(format!("Failed to create Emulator: {}", e)))?;

        // Apply permissive memory option if requested (default is true)
        if config.permissive_memory.unwrap_or(true) {
            emulator
                .set_permissive_memory(true)
                .map_err(|e| Error::from_reason(format!("Failed to set permissive memory: {}", e)))?;
        }

        Ok(Self {
            inner: Some(emulator),
            disposed: false,
            max_instructions: config.max_instructions.map(|m| m as u64).unwrap_or(1_000_000),
            verbose: config.verbose.unwrap_or(false),
        })
    }

    /// Load a binary into the emulator.
    /// Returns the entry point address.
    #[napi]
    pub fn load(&mut self, data: Buffer) -> Result<BigInt> {
        self.check_disposed()?;
        let inner = self.inner.as_mut().unwrap();
        let entry = inner
            .load(data.as_ref())
            .map_err(|e| Error::from_reason(format!("Load failed: {}", e)))?;

        if self.verbose {
            eprintln!("[Elixir] Loaded binary, entry point: 0x{:x}", entry);
        }

        Ok(BigInt::from(entry as i64))
    }

    /// Start emulation from the given address.
    /// end=0 means run until stop() or until max_instructions is reached.
    #[napi]
    pub fn run(&mut self, start: BigInt, end: BigInt) -> Result<JsStopReason> {
        self.check_disposed()?;
        let inner = self.inner.as_mut().unwrap();

        let start_addr = start.get_u64().1;
        let end_addr = end.get_u64().1;

        if self.verbose {
            eprintln!(
                "[Elixir] Running from 0x{:x} to 0x{:x}, max_insns={}",
                start_addr, end_addr, self.max_instructions
            );
        }

        // Run emulation - capture result but don't fail on non-fatal errors
        // (G4 test shows UC_ERR_EXCEPTION can still result in clean exit via API hooks)
        let run_result = inner.run(start_addr, end_addr, self.max_instructions);
        if let Err(ref e) = run_result {
            if self.verbose {
                eprintln!("[Elixir] run() returned: {:?}", e);
            }
        }

        // Get stop reason - this is the authoritative result
        let reason = inner.stop_reason();
        let _api_count = inner.api_log_count();

        let (kind, message) = match reason {
            elixir_core::types::SimpleStopReason::Exit => ("exit", "Program exited normally".to_string()),
            elixir_core::types::SimpleStopReason::InsnLimit => {
                ("insn_limit", format!("Instruction limit reached ({})", self.max_instructions))
            }
            elixir_core::types::SimpleStopReason::Error => ("error", "Emulation error".to_string()),
            elixir_core::types::SimpleStopReason::User => ("user", "User requested stop".to_string()),
            elixir_core::types::SimpleStopReason::Breakpoint => {
                ("breakpoint", "Breakpoint hit".to_string())
            }
            elixir_core::types::SimpleStopReason::None => ("none", "No stop reason available".to_string()),
        };

        // Read actual RIP (x86_64 register ID 41 in Unicorn = UC_X86_REG_RIP)
        let ip_value = inner.reg_read(41).unwrap_or(0);

        // Get actual instruction count from engine
        let instructions_executed = inner.instruction_count();

        Ok(JsStopReason {
            kind: kind.to_string(),
            address: BigInt::from(ip_value as i64),
            instructions_executed: instructions_executed as i64,
            message,
        })
    }

    /// Stop emulation (can be called from another thread).
    #[napi]
    pub fn stop(&mut self) -> Result<()> {
        self.check_disposed()?;
        let inner = self.inner.as_mut().unwrap();
        inner
            .stop()
            .map_err(|e| Error::from_reason(format!("Stop failed: {}", e)))?;
        Ok(())
    }

    /// Get the number of API calls logged.
    #[napi]
    pub fn get_api_call_count(&mut self) -> Result<i64> {
        self.check_disposed()?;
        let inner = self.inner.as_ref().unwrap();
        Ok(inner.api_log_count() as i64)
    }

    /// Get API call log (returns count for now as summary).
    /// TODO: Return detailed per-call records when API is available.
    #[napi]
    pub fn get_api_calls(&mut self) -> Result<Vec<JsApiCall>> {
        self.check_disposed()?;
        let inner = self.inner.as_ref().unwrap();
        let count = inner.api_log_count();

        // Return a single summary entry for now
        // Future: iterate actual API call records
        Ok(vec![JsApiCall {
            name: format!("api_log_count_{}", count),
            address: BigInt::from(0i64),
            return_value: BigInt::from(count as i64),
        }])
    }

    /// Read a register value.
    /// reg_id: Unicorn register ID (e.g., UC_X86_REG_RAX = 19).
    #[napi]
    pub fn reg_read(&mut self, reg_id: i32) -> Result<BigInt> {
        self.check_disposed()?;
        let inner = self.inner.as_mut().unwrap();
        let value = inner
            .reg_read(reg_id as u32)
            .map_err(|e| Error::from_reason(format!("Register read failed: {}", e)))?;
        Ok(BigInt::from(value as i64))
    }

    /// Write a register value.
    #[napi]
    pub fn reg_write(&mut self, reg_id: i32, value: BigInt) -> Result<()> {
        self.check_disposed()?;
        let inner = self.inner.as_mut().unwrap();
        let val = value.get_u64().1;
        inner
            .reg_write(reg_id as u32, val)
            .map_err(|e| Error::from_reason(format!("Register write failed: {}", e)))?;
        Ok(())
    }

    /// Read memory from the emulator.
    #[napi]
    pub fn mem_read(&mut self, addr: BigInt, size: i64) -> Result<Buffer> {
        self.check_disposed()?;
        let inner = self.inner.as_mut().unwrap();
        let address = addr.get_u64().1;
        let len = size as usize;

        let mut buf = vec![0u8; len];
        inner
            .mem_read(address, &mut buf)
            .map_err(|e| Error::from_reason(format!("Memory read failed: {}", e)))?;

        Ok(Buffer::from(buf))
    }

    /// Write memory to the emulator.
    #[napi]
    pub fn mem_write(&mut self, addr: BigInt, data: Buffer) -> Result<()> {
        self.check_disposed()?;
        let inner = self.inner.as_mut().unwrap();
        let address = addr.get_u64().1;

        inner
            .mem_write(address, data.as_ref())
            .map_err(|e| Error::from_reason(format!("Memory write failed: {}", e)))?;
        Ok(())
    }

    /// Map a memory region.
    #[napi]
    pub fn mem_map(&mut self, addr: BigInt, size: BigInt, prot: i32) -> Result<()> {
        self.check_disposed()?;
        let inner = self.inner.as_mut().unwrap();
        let address = addr.get_u64().1;
        let len = size.get_u64().1;
        let protection = elixir_core::types::MemProt::from_bits(prot as u32)
            .unwrap_or(elixir_core::types::MemProt::RWX);

        inner
            .mem_map(address, len, protection)
            .map_err(|e| Error::from_reason(format!("Memory map failed: {}", e)))?;
        Ok(())
    }

    /// Attach an interceptor hook at the given address.
    #[napi]
    pub fn interceptor_attach(&mut self, address: BigInt) -> Result<()> {
        self.check_disposed()?;
        let inner = self.inner.as_mut().unwrap();
        let addr = address.get_u64().1;
        inner
            .interceptor_attach(addr)
            .map_err(|e| Error::from_reason(format!("Interceptor attach failed: {}", e)))?;
        Ok(())
    }

    /// Detach an interceptor hook at the given address.
    #[napi]
    pub fn interceptor_detach(&mut self, address: BigInt) -> Result<()> {
        self.check_disposed()?;
        let inner = self.inner.as_mut().unwrap();
        let addr = address.get_u64().1;
        inner
            .interceptor_detach(addr)
            .map_err(|e| Error::from_reason(format!("Interceptor detach failed: {}", e)))?;
        Ok(())
    }

    /// Get interceptor log count.
    #[napi]
    pub fn interceptor_log_count(&mut self) -> Result<i64> {
        self.check_disposed()?;
        let inner = self.inner.as_ref().unwrap();
        Ok(inner.interceptor_log_count() as i64)
    }

    /// Enable Stalker tracing.
    #[napi]
    pub fn stalker_follow(&mut self) -> Result<()> {
        self.check_disposed()?;
        let inner = self.inner.as_mut().unwrap();
        inner
            .stalker_follow()
            .map_err(|e| Error::from_reason(format!("Stalker follow failed: {}", e)))?;
        Ok(())
    }

    /// Disable Stalker tracing.
    #[napi]
    pub fn stalker_unfollow(&mut self) -> Result<()> {
        self.check_disposed()?;
        let inner = self.inner.as_mut().unwrap();
        inner
            .stalker_unfollow()
            .map_err(|e| Error::from_reason(format!("Stalker unfollow failed: {}", e)))?;
        Ok(())
    }

    /// Get Stalker block count.
    #[napi]
    pub fn stalker_block_count(&mut self) -> Result<i64> {
        self.check_disposed()?;
        let inner = self.inner.as_ref().unwrap();
        Ok(inner.stalker_block_count() as i64)
    }

    /// Export Stalker coverage as DRCOV format.
    #[napi]
    pub fn stalker_export_drcov(&mut self) -> Result<Buffer> {
        self.check_disposed()?;
        let inner = self.inner.as_ref().unwrap();
        let data = inner
            .stalker_export_drcov()
            .map_err(|e| Error::from_reason(format!("Stalker export failed: {}", e)))?;
        Ok(Buffer::from(data))
    }

    /// Save a snapshot of the current emulation state.
    #[napi]
    pub fn snapshot_save(&self) -> Result<Buffer> {
        self.check_disposed()?;
        let inner = self.inner.as_ref().unwrap();
        let data = inner
            .snapshot_save()
            .map_err(|e| Error::from_reason(format!("Snapshot save failed: {}", e)))?;
        Ok(Buffer::from(data))
    }

    /// Restore from a snapshot.
    #[napi]
    pub fn snapshot_restore(&mut self, blob: Buffer) -> Result<()> {
        self.check_disposed()?;
        let inner = self.inner.as_mut().unwrap();
        inner
            .snapshot_restore(blob.as_ref())
            .map_err(|e| Error::from_reason(format!("Snapshot restore failed: {}", e)))?;
        Ok(())
    }

    /// Release emulator resources. The emulator cannot be used after this call.
    #[napi]
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.inner = None;
    }

    /// Check if the emulator has been disposed.
    #[napi(getter)]
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Get the maximum instruction limit.
    #[napi(getter)]
    pub fn max_instructions(&self) -> i64 {
        self.max_instructions as i64
    }

    /// Set the maximum instruction limit.
    #[napi(setter)]
    pub fn set_max_instructions(&mut self, value: i64) {
        self.max_instructions = value as u64;
    }

    // Helper to check disposed state
    fn check_disposed(&self) -> Result<()> {
        if self.disposed {
            Err(Error::from_reason(
                "Emulator has been disposed. Create a new instance.",
            ))
        } else {
            Ok(())
        }
    }
}

// ─── Interceptor Class ───────────────────────────────────────────────────────

/// Interceptor for hooking function calls.
///
/// Usage from TypeScript:
/// ```typescript
/// const interceptor = new Interceptor(emulator);
/// interceptor.attach(0x401000n);
/// // ... run emulation ...
/// interceptor.detach(0x401000n);
/// ```
#[napi]
pub struct Interceptor {
    disposed: bool,
}

#[napi]
impl Interceptor {
    /// Create a new Interceptor attached to an Emulator.
    /// Note: The Emulator must outlive the Interceptor.
    #[napi(constructor)]
    pub fn new(_emulator: &Emulator) -> Result<Self> {
        // We don't store the emulator reference directly to avoid lifetime issues.
        // Instead, users call attach/detach on the Emulator directly,
        // or we provide convenience methods that delegate.
        Ok(Self { disposed: false })
    }

    /// Attach a hook at the given address.
    /// This is a convenience method that delegates to Emulator.interceptor_attach().
    #[napi]
    pub fn attach(&mut self, emulator: &mut Emulator, address: BigInt) -> Result<()> {
        if self.disposed {
            return Err(Error::from_reason("Interceptor has been disposed."));
        }
        emulator.interceptor_attach(address)
    }

    /// Detach a hook at the given address.
    #[napi]
    pub fn detach(&mut self, emulator: &mut Emulator, address: BigInt) -> Result<()> {
        if self.disposed {
            return Err(Error::from_reason("Interceptor has been disposed."));
        }
        emulator.interceptor_detach(address)
    }

    /// Release interceptor resources.
    #[napi]
    pub fn dispose(&mut self) {
        self.disposed = true;
    }

    /// Check if the interceptor has been disposed.
    #[napi(getter)]
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }
}

// ─── Stalker Class ───────────────────────────────────────────────────────────

/// Stalker for code coverage and tracing.
///
/// Usage from TypeScript:
/// ```typescript
/// const stalker = new Stalker(emulator);
/// stalker.follow();
/// // ... run emulation ...
/// stalker.unfollow();
/// const drcov = stalker.exportDrcov();
/// ```
#[napi]
pub struct Stalker {
    disposed: bool,
}

#[napi]
impl Stalker {
    /// Create a new Stalker attached to an Emulator.
    #[napi(constructor)]
    pub fn new(_emulator: &Emulator) -> Result<Self> {
        Ok(Self { disposed: false })
    }

    /// Start following code execution.
    #[napi]
    pub fn follow(&mut self, emulator: &mut Emulator) -> Result<()> {
        if self.disposed {
            return Err(Error::from_reason("Stalker has been disposed."));
        }
        emulator.stalker_follow()
    }

    /// Stop following code execution.
    #[napi]
    pub fn unfollow(&mut self, emulator: &mut Emulator) -> Result<()> {
        if self.disposed {
            return Err(Error::from_reason("Stalker has been disposed."));
        }
        emulator.stalker_unfollow()
    }

    /// Get the number of basic blocks traced.
    #[napi]
    pub fn block_count(&self, emulator: &mut Emulator) -> Result<i64> {
        if self.disposed {
            return Err(Error::from_reason("Stalker has been disposed."));
        }
        emulator.stalker_block_count()
    }

    /// Drain traced events (returns empty for now, use exportDrcov instead).
    /// TODO: Implement block event iteration when API is available.
    #[napi]
    pub fn drain(&mut self, emulator: &mut Emulator) -> Result<Vec<JsStalkerEvent>> {
        if self.disposed {
            return Err(Error::from_reason("Stalker has been disposed."));
        }
        // Return empty vector; actual block iteration requires C++ API expansion
        let count = emulator.stalker_block_count()?;

        // Return a summary event
        Ok(vec![JsStalkerEvent {
            from: BigInt::from(0i64),
            to: BigInt::from(0i64),
            count: count,
        }])
    }

    /// Export coverage data in DRCOV format.
    #[napi]
    pub fn export_drcov(&mut self, emulator: &mut Emulator) -> Result<Buffer> {
        if self.disposed {
            return Err(Error::from_reason("Stalker has been disposed."));
        }
        emulator.stalker_export_drcov()
    }

    /// Release stalker resources.
    #[napi]
    pub fn dispose(&mut self) {
        self.disposed = true;
    }

    /// Check if the stalker has been disposed.
    #[napi(getter)]
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }
}

// ─── Snapshot Functions (standalone) ─────────────────────────────────────────

/// Save a snapshot of the emulator state.
/// Returns a Buffer containing the serialized state.
#[napi]
pub fn snapshot_save(emulator: &Emulator) -> Result<Buffer> {
    emulator.snapshot_save()
}

/// Restore emulator state from a snapshot.
#[napi]
pub fn snapshot_restore(emulator: &mut Emulator, blob: Buffer) -> Result<()> {
    emulator.snapshot_restore(blob)
}

// ─── Helper Functions ────────────────────────────────────────────────────────

fn parse_arch(s: &str) -> Result<elixir_core::types::Arch> {
    match s.to_lowercase().as_str() {
        "x86" | "i386" | "i686" => Ok(elixir_core::types::Arch::X86),
        "x86_64" | "x64" | "amd64" => Ok(elixir_core::types::Arch::X86_64),
        "arm" | "arm32" => Ok(elixir_core::types::Arch::Arm),
        "arm64" | "aarch64" => Ok(elixir_core::types::Arch::Arm64),
        _ => Err(Error::from_reason(format!(
            "Unsupported architecture: '{}'. Supported: x86, x86_64, arm, arm64",
            s
        ))),
    }
}

fn parse_os(s: &str) -> Result<elixir_core::types::OsType> {
    match s.to_lowercase().as_str() {
        "linux" | "ubuntu" | "debian" | "redhat" | "centos" => Ok(elixir_core::types::OsType::Linux),
        "windows" | "win32" | "win" => Ok(elixir_core::types::OsType::Windows),
        "macos" | "mac" | "darwin" | "osx" => Ok(elixir_core::types::OsType::MacOS),
        "bare" | "none" => Ok(elixir_core::types::OsType::Bare),
        _ => Err(Error::from_reason(format!(
            "Unsupported OS: '{}'. Supported: linux, windows, macos, bare",
            s
        ))),
    }
}
