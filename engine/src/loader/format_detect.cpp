// HexCore Elixir — Binary Format Detection
//
// Clean-room implementation using:
//   - Microsoft PE specification (MZ/PE magic)
//   - ELF specification (0x7F ELF magic)
//   - Apple Mach-O specification (feed face/cafe babe magic)
//
// Apache-2.0 licensed. No code copied verbatim.

#include "elixir/engine_internal.h"
#include <cstdint>
#include <cstring>

BinaryFormat detect_format(const uint8_t* data, uint64_t len) {
    if (!data || len < 4) return BinaryFormat::Unknown;
    
    // PE: MZ header
    if (len >= 2 && data[0] == 0x4D && data[1] == 0x5A) return BinaryFormat::PE;
    
    // ELF: 0x7F ELF
    if (len >= 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F')
        return BinaryFormat::ELF;
    
    // Mach-O: FE ED FA CE (32-bit) or FE ED FA CF (64-bit)
    if (len >= 4) {
        uint32_t magic = *(const uint32_t*)data;
        if (magic == 0xFEEDFACE || magic == 0xFEEDFACF ||
            magic == 0xCEFAEDFE || magic == 0xCFFAEDFE ||  // reversed
            magic == 0xCAFEBABE || magic == 0xBEBAFECA)     // universal
            return BinaryFormat::MachO;
    }
    
    return BinaryFormat::Unknown;
}
