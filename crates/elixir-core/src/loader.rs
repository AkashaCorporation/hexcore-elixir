// elixir_core — Binary Loader
//
// Tier 2 (elixir_ldr): Parses binary formats, maps sections, resolves imports,
// and sets up Thread Local Storage (TLS).
//
// Supported formats:
//   - PE (Windows executables and DLLs)
//   - ELF (Linux/BSD/Android)
//   - Mach-O (macOS/iOS)
//   - Raw (flat binary, no format)

use crate::error::ElixirResult;
use crate::types::{Arch, BinaryFormat};

/// Result of loading a binary
#[derive(Debug, Clone)]
pub struct LoadResult {
    pub format: BinaryFormat,
    pub arch: Arch,
    pub entry_point: u64,
    pub base_address: u64,
    pub image_size: u64,
    /// Import table: (module, function_name, iat_address)
    pub imports: Vec<(String, String, u64)>,
    /// Export table: (function_name, rva)
    pub exports: Vec<(String, u64)>,
}

/// Detect the binary format from magic bytes
pub fn detect_format(data: &[u8]) -> Option<BinaryFormat> {
    if data.len() < 4 {
        return None;
    }
    match &data[..4] {
        [0x4D, 0x5A, ..] => Some(BinaryFormat::PE),       // MZ
        [0x7F, 0x45, 0x4C, 0x46] => Some(BinaryFormat::ELF), // \x7FELF
        [0xFE, 0xED, 0xFA, 0xCE] => Some(BinaryFormat::MachO), // Mach-O 32
        [0xFE, 0xED, 0xFA, 0xCF] => Some(BinaryFormat::MachO), // Mach-O 64
        [0xCE, 0xFA, 0xED, 0xFE] => Some(BinaryFormat::MachO), // Mach-O 32 LE
        [0xCF, 0xFA, 0xED, 0xFE] => Some(BinaryFormat::MachO), // Mach-O 64 LE
        _ => None,
    }
}

/// Load a PE binary
pub fn load_pe(_data: &[u8]) -> ElixirResult<LoadResult> {
    // TODO: Parse DOS header, PE header, sections, imports, exports, TLS
    // Reference: Microsoft PE/COFF spec (public domain)
    todo!("PE loader")
}

/// Load an ELF binary
pub fn load_elf(_data: &[u8]) -> ElixirResult<LoadResult> {
    // TODO: Parse ELF header, program headers, sections, dynamic linking
    // Reference: ELF spec (refspecs.linuxfoundation.org)
    todo!("ELF loader")
}

/// Load a Mach-O binary
pub fn load_macho(_data: &[u8]) -> ElixirResult<LoadResult> {
    // TODO: Parse Mach-O header, load commands, segments
    // Reference: Apple Mach-O docs
    todo!("Mach-O loader")
}
