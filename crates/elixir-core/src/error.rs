use thiserror::Error;

#[derive(Error, Debug)]
pub enum ElixirError {
    #[error("Unicorn engine error: {0}")]
    Unicorn(String),

    #[error("Loader error: {0}")]
    Loader(String),

    #[error("OS subsystem error: {0}")]
    OsSubsystem(String),

    #[error("Instrumentation error: {0}")]
    Instrument(String),

    #[error("Snapshot error: {0}")]
    Snapshot(String),

    #[error("Memory error at 0x{addr:x}: {reason}")]
    Memory { addr: u64, reason: String },

    #[error("Unsupported architecture: {0}")]
    UnsupportedArch(String),

    #[error("Unsupported OS: {0}")]
    UnsupportedOs(String),

    #[error("FFI error: {0}")]
    Ffi(String),
}

pub type ElixirResult<T> = Result<T, ElixirError>;
