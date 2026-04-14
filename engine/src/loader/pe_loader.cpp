// HexCore Elixir — PE64 Loader
//
// Clean-room implementation using:
//   - Microsoft PE/COFF specification
//   - handoff/specs/data-import-detection.md
//   - handoff/specs/peb-ldr-data-layout.md (memory constants)
//
// Apache-2.0 licensed. No code copied verbatim.

// Prevent Windows SDK from defining min/max macros
#define NOMINMAX

#include "elixir/engine_internal.h"
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <regex>
#include <map>

// PE Header Structures (packed) - Elixir namespace to avoid conflicts with Windows SDK
#pragma pack(push, 1)

namespace elixir_pe {

struct DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

struct FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    DATA_DIRECTORY DataDirectory[16];
};

struct SECTION_HEADER {
    uint8_t Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct IMPORT_DESCRIPTOR {
    uint32_t OriginalFirstThunk;  // ILT RVA
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;          // IAT RVA
};

struct BASE_RELOCATION {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
};

struct TLS_DIRECTORY64 {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;
    uint64_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};

} // namespace elixir_pe

#pragma pack(pop)

// Type aliases for cleaner code
using namespace elixir_pe;

// Constants (prefixed with ELIXIR_ to avoid Windows SDK conflicts)
constexpr uint16_t ELIXIR_DOS_SIGNATURE = 0x5A4D;
constexpr uint32_t ELIXIR_NT_SIGNATURE = 0x00004550;
constexpr uint16_t ELIXIR_MACHINE_AMD64 = 0x8664;
constexpr uint16_t ELIXIR_MAGIC_PE32PLUS = 0x020B;

// Section characteristics
constexpr uint32_t SCN_MEM_EXECUTE = 0x20000000;
constexpr uint32_t SCN_MEM_READ = 0x40000000;
constexpr uint32_t SCN_MEM_WRITE = 0x80000000;

// Relocation types
constexpr uint16_t REL_BASED_ABSOLUTE = 0;
constexpr uint16_t REL_BASED_DIR64 = 10;

// Memory layout constants from peb-ldr-data-layout.md
constexpr uint64_t STUB_BASE = 0x70000000;
constexpr uint64_t DATA_IMPORT_BASE = 0x71000000;
constexpr uint64_t STUB_REGION_SIZE = 0x100000;       // 1 MB
constexpr uint64_t DATA_IMPORT_REGION_SIZE = 0x800000; // 8 MB
constexpr uint64_t DATA_IMPORT_BLOCK_SIZE = 0x1000;    // 4 KB per block
constexpr uint64_t TLS_STORAGE_BASE = 0x7FFB0000;
constexpr uint64_t TLS_VECTOR_ADDRESS = 0x7FFC0000;

// Data Directory indices
constexpr int DIR_ENTRY_IMPORT = 1;
constexpr int DIR_ENTRY_BASERELOC = 5;
constexpr int DIR_ENTRY_TLS = 9;

// Helper: Convert section characteristics to Unicorn protection
static uint32_t section_prot_to_unicorn(uint32_t characteristics) {
    uint32_t prot = 0;
    if (characteristics & SCN_MEM_READ)    prot |= UC_PROT_READ;
    if (characteristics & SCN_MEM_WRITE)   prot |= UC_PROT_WRITE;
    if (characteristics & SCN_MEM_EXECUTE) prot |= UC_PROT_EXEC;
    return prot;
}

// Helper: Align value up to alignment
static uint64_t align_up(uint64_t value, uint64_t alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

// Helper: Read null-terminated string from file data at offset
static std::string read_string_at(const uint8_t* data, uint64_t len, uint64_t offset) {
    if (offset >= len) return "";
    const char* str = reinterpret_cast<const char*>(data + offset);
    size_t max_len = static_cast<size_t>(len - offset);
    size_t str_len = strnlen(str, max_len);
    return std::string(str, str_len);
}

// Data import detection per data-import-detection.md
// Regex: ^\?[A-Za-z_]\w*(?:@[A-Za-z_]\w*)+@@[0-9]
static bool is_data_import(const std::string& name) {
    // Pre-filter: reject anything starting with "??" (operators, always functions)
    if (name.size() >= 2 && name[0] == '?' && name[1] == '?') {
        return false;
    }
    
    // Must start with '?'
    if (name.empty() || name[0] != '?') {
        return false;
    }
    
    // Must contain "@@" followed by a digit
    size_t atat_pos = name.find("@@");
    if (atat_pos == std::string::npos || atat_pos + 2 >= name.size()) {
        return false;
    }
    
    char storage_class = name[atat_pos + 2];
    if (storage_class < '0' || storage_class > '9') {
        return false;
    }
    
    // Must have at least one @-prefixed scope before @@
    // Check that there's at least one '@' between '?' and '@@'
    bool has_scope = false;
    for (size_t i = 1; i < atat_pos; ++i) {
        if (name[i] == '@') {
            has_scope = true;
            break;
        }
    }
    
    return has_scope;
}

// PE Loader implementation
ElixirError pe_load(ElixirContext* ctx, const uint8_t* data, uint64_t len, uint64_t* entry_point, std::vector<ImportEntry>* out_imports, uint64_t* out_image_base) {
    if (!ctx || !ctx->uc || !ctx->mem || !data || len == 0 || !entry_point) {
        return ELIXIR_ERR_ARGS;
    }
    
    // Clear any existing imports
    if (out_imports) {
        out_imports->clear();
    }
    
    *entry_point = 0;
    if (out_image_base) {
        *out_image_base = 0;
    }
    
    // === A. Header Parsing ===
    
    // Check minimum size for DOS header
    if (len < sizeof(DOS_HEADER)) {
        return ELIXIR_ERR_LOADER;
    }
    
    // Parse DOS header
    const DOS_HEADER* dos_hdr = reinterpret_cast<const DOS_HEADER*>(data);
    if (dos_hdr->e_magic != ELIXIR_DOS_SIGNATURE) {
        return ELIXIR_ERR_LOADER;
    }
    
    // Check PE signature
    if (dos_hdr->e_lfanew + sizeof(uint32_t) > len) {
        return ELIXIR_ERR_LOADER;
    }
    uint32_t pe_sig = *reinterpret_cast<const uint32_t*>(data + dos_hdr->e_lfanew);
    if (pe_sig != ELIXIR_NT_SIGNATURE) {
        return ELIXIR_ERR_LOADER;
    }
    
    // Check COFF header
    uint64_t coff_offset = dos_hdr->e_lfanew + sizeof(uint32_t);
    if (coff_offset + sizeof(FILE_HEADER) > len) {
        return ELIXIR_ERR_LOADER;
    }
    const FILE_HEADER* coff_hdr = reinterpret_cast<const FILE_HEADER*>(data + coff_offset);
    
    // Verify AMD64 machine type
    if (coff_hdr->Machine != ELIXIR_MACHINE_AMD64) {
        return ELIXIR_ERR_LOADER;
    }
    
    // Parse optional header (PE32+)
    uint64_t opt_offset = coff_offset + sizeof(FILE_HEADER);
    if (opt_offset + sizeof(OPTIONAL_HEADER64) > len) {
        return ELIXIR_ERR_LOADER;
    }
    const OPTIONAL_HEADER64* opt_hdr = reinterpret_cast<const OPTIONAL_HEADER64*>(data + opt_offset);
    
    // Verify PE32+ magic
    if (opt_hdr->Magic != ELIXIR_MAGIC_PE32PLUS) {
        return ELIXIR_ERR_LOADER;
    }
    
    // Extract key values
    uint64_t image_base = opt_hdr->ImageBase;
    uint32_t section_alignment = opt_hdr->SectionAlignment;
    uint32_t file_alignment = opt_hdr->FileAlignment;
    uint32_t entry_point_rva = opt_hdr->AddressOfEntryPoint;
    uint32_t size_of_image = opt_hdr->SizeOfImage;
    uint32_t num_data_dirs = opt_hdr->NumberOfRvaAndSizes;
    uint16_t num_sections = coff_hdr->NumberOfSections;
    
    if (section_alignment == 0) section_alignment = 0x1000;
    if (file_alignment == 0) file_alignment = 0x200;
    
    // Calculate entry point VA
    *entry_point = image_base + entry_point_rva;
    
    // Return image base if requested
    if (out_image_base) {
        *out_image_base = image_base;
    }
    
    // === B. Section Mapping ===
    
    // Map PE headers (first SectionAlignment bytes at image_base)
    uint64_t headers_size = align_up(opt_hdr->SizeOfHeaders, section_alignment);
    ElixirError err = ctx->mem->map(image_base, headers_size, UC_PROT_READ, "PE_HEADERS");
    if (err != ELIXIR_OK) {
        return err;
    }
    
    // Write headers to emulated memory
    uc_err uc_err_code = uc_mem_write(ctx->uc, image_base, data, 
                                       std::min<uint64_t>(opt_hdr->SizeOfHeaders, len));
    if (uc_err_code != UC_ERR_OK) {
        return ELIXIR_ERR_MEMORY;
    }
    
    // Parse section headers
    uint64_t sect_offset = opt_offset + coff_hdr->SizeOfOptionalHeader;
    
    for (uint16_t i = 0; i < num_sections; ++i) {
        if (sect_offset + sizeof(SECTION_HEADER) > len) {
            return ELIXIR_ERR_LOADER;
        }
        
        const SECTION_HEADER* sect = reinterpret_cast<const SECTION_HEADER*>(data + sect_offset);
        sect_offset += sizeof(SECTION_HEADER);
        
        // Skip empty sections
        if (sect->VirtualSize == 0 && sect->SizeOfRawData == 0) {
            continue;
        }
        
        // Calculate virtual address and size
        uint64_t va = image_base + sect->VirtualAddress;
        uint64_t virtual_size = std::max(sect->VirtualSize, sect->SizeOfRawData);
        virtual_size = align_up(virtual_size, section_alignment);
        
        // Determine protection
        uint32_t prot = section_prot_to_unicorn(sect->Characteristics);
        if (prot == 0) prot = UC_PROT_READ;  // Default to read-only
        
        // Get section name
        char name_buf[9] = {0};
        std::memcpy(name_buf, sect->Name, 8);
        std::string sect_name(name_buf);
        
        // Map section
        err = ctx->mem->map(va, virtual_size, prot, sect_name);
        if (err != ELIXIR_OK) {
            return err;
        }
        
        // Copy raw data if present
        if (sect->SizeOfRawData > 0 && sect->PointerToRawData < len) {
            uint64_t data_to_copy = std::min<uint64_t>(sect->SizeOfRawData, 
                                                        len - sect->PointerToRawData);
            uint64_t data_to_write = std::min(data_to_copy, virtual_size);
            
            if (data_to_write > 0) {
                uc_err_code = uc_mem_write(ctx->uc, va, data + sect->PointerToRawData, 
                                           static_cast<size_t>(data_to_write));
                if (uc_err_code != UC_ERR_OK) {
                    return ELIXIR_ERR_MEMORY;
                }
            }
        }
    }
    
    // === C. Import Address Table (IAT) with Data Import Detection ===
    
    // Map STUB_BASE region (1MB, RX) for function stubs
    err = ctx->mem->map(STUB_BASE, STUB_REGION_SIZE, UC_PROT_READ | UC_PROT_EXEC, "STUB_REGION");
    if (err != ELIXIR_OK) {
        return err;
    }
    
    // Map DATA_IMPORT_BASE region (8MB, RW) for data import blocks
    err = ctx->mem->map(DATA_IMPORT_BASE, DATA_IMPORT_REGION_SIZE, UC_PROT_READ | UC_PROT_WRITE, "DATA_IMPORT");
    if (err != ELIXIR_OK) {
        return err;
    }
    
    // Track offsets for stub/data allocation
    uint64_t stub_offset = 0;
    uint64_t data_import_offset = 0;
    
    // Process import directory if present
    if (num_data_dirs > DIR_ENTRY_IMPORT && 
        opt_hdr->DataDirectory[DIR_ENTRY_IMPORT].VirtualAddress != 0) {
        
        uint32_t import_dir_rva = opt_hdr->DataDirectory[DIR_ENTRY_IMPORT].VirtualAddress;
        uint32_t import_dir_size = opt_hdr->DataDirectory[DIR_ENTRY_IMPORT].Size;
        
        // Iterate import descriptors
        uint32_t desc_offset = import_dir_rva;
        while (desc_offset < import_dir_rva + import_dir_size) {
            if (desc_offset + sizeof(IMPORT_DESCRIPTOR) > size_of_image) {
                break;
            }
            
            // Read descriptor from emulated memory
            IMPORT_DESCRIPTOR desc;
            uc_err_code = uc_mem_read(ctx->uc, image_base + desc_offset, &desc, sizeof(desc));
            if (uc_err_code != UC_ERR_OK) {
                break;
            }
            
            // Check for terminator (all zeros)
            if (desc.OriginalFirstThunk == 0 && desc.Name == 0 && desc.FirstThunk == 0) {
                break;
            }
            
            // Get DLL name
            std::string dll_name;
            if (desc.Name != 0 && desc.Name < size_of_image) {
                char name_buf[256] = {0};
                uc_mem_read(ctx->uc, image_base + desc.Name, name_buf, sizeof(name_buf) - 1);
                dll_name = name_buf;
            }
            
            // Process import lookup table (ILT)
            uint32_t ilt_rva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
            uint32_t iat_rva = desc.FirstThunk;
            
            if (ilt_rva != 0 && iat_rva != 0) {
                uint32_t thunk_idx = 0;
                while (true) {
                    uint64_t thunk_data = 0;
                    uint64_t ilt_va = image_base + ilt_rva + thunk_idx * sizeof(uint64_t);
                    uint64_t iat_va = image_base + iat_rva + thunk_idx * sizeof(uint64_t);
                    
                    uc_err_code = uc_mem_read(ctx->uc, ilt_va, &thunk_data, sizeof(thunk_data));
                    if (uc_err_code != UC_ERR_OK || thunk_data == 0) {
                        break;
                    }
                    
                    // Check if import by ordinal (high bit set)
                    bool is_ordinal = (thunk_data & (1ULL << 63)) != 0;
                    
                    if (is_ordinal) {
                        // Import by ordinal - treat as function
                        uint64_t stub_addr = STUB_BASE + stub_offset;
                        uint8_t ret_insn = 0xC3;
                        uc_mem_write(ctx->uc, stub_addr, &ret_insn, 1);
                        
                        // Record import entry
                        if (out_imports) {
                            ImportEntry entry;
                            entry.dll_name = dll_name;
                            entry.func_name = "ordinal_" + std::to_string(thunk_data & 0xFFFF);
                            entry.stub_addr = stub_addr;
                            entry.is_data_import = false;
                            out_imports->push_back(entry);
                        }
                        
                        stub_offset += 16;  // 16-byte alignment for stubs
                        
                        // Write stub address to IAT
                        uc_mem_write(ctx->uc, iat_va, &stub_addr, sizeof(stub_addr));
                    } else {
                        // Import by name
                        uint32_t hint_name_rva = static_cast<uint32_t>(thunk_data & 0xFFFFFFFF);
                        if (hint_name_rva < size_of_image) {
                            // Read hint (2 bytes) then name
                            uint16_t hint = 0;
                            uc_mem_read(ctx->uc, image_base + hint_name_rva, &hint, sizeof(hint));
                            
                            char name_buf[512] = {0};
                            uc_mem_read(ctx->uc, image_base + hint_name_rva + 2, name_buf, sizeof(name_buf) - 1);
                            std::string import_name(name_buf);
                            
                            if (is_data_import(import_name)) {
                                // Data import: allocate 4KB block
                                if (data_import_offset + DATA_IMPORT_BLOCK_SIZE <= DATA_IMPORT_REGION_SIZE) {
                                    uint64_t block_addr = DATA_IMPORT_BASE + data_import_offset;
                                    
                                    // Write self+0x100 at offset 0 (pointer to fake vbtable)
                                    uint64_t self_ptr = block_addr + 0x100;
                                    uc_mem_write(ctx->uc, block_addr, &self_ptr, sizeof(self_ptr));
                                    
                                    // Rest is already zero (mapped as fresh memory)
                                    
                                    // Write block address to IAT entry
                                    uc_mem_write(ctx->uc, iat_va, &block_addr, sizeof(block_addr));
                                    
                                    // Record import entry
                                    if (out_imports) {
                                        ImportEntry entry;
                                        entry.dll_name = dll_name;
                                        entry.func_name = import_name;
                                        entry.stub_addr = block_addr;
                                        entry.is_data_import = true;
                                        out_imports->push_back(entry);
                                    }
                                    
                                    data_import_offset += DATA_IMPORT_BLOCK_SIZE;
                                }
                            } else {
                                // Function import: write RET stub
                                if (stub_offset + 16 <= STUB_REGION_SIZE) {
                                    uint64_t stub_addr = STUB_BASE + stub_offset;
                                    uint8_t ret_insn = 0xC3;
                                    uc_mem_write(ctx->uc, stub_addr, &ret_insn, 1);
                                    
                                    // Record import entry
                                    if (out_imports) {
                                        ImportEntry entry;
                                        entry.dll_name = dll_name;
                                        entry.func_name = import_name;
                                        entry.stub_addr = stub_addr;
                                        entry.is_data_import = false;
                                        out_imports->push_back(entry);
                                    }
                                    
                                    stub_offset += 16;
                                    
                                    // Write stub address to IAT entry
                                    uc_mem_write(ctx->uc, iat_va, &stub_addr, sizeof(stub_addr));
                                }
                            }
                        }
                    }
                    
                    thunk_idx++;
                }
            }
            
            desc_offset += sizeof(IMPORT_DESCRIPTOR);
        }
    }
    
    // === D. Relocations ===
    
    // Check if we need to apply relocations (if loaded at different base)
    // For now, we load at preferred ImageBase, so skip relocations
    // TODO: Implement base relocation if dynamic base loading is needed
    
    // === E. TLS Setup ===
    
    if (num_data_dirs > DIR_ENTRY_TLS && 
        opt_hdr->DataDirectory[DIR_ENTRY_TLS].VirtualAddress != 0) {
        
        uint32_t tls_dir_rva = opt_hdr->DataDirectory[DIR_ENTRY_TLS].VirtualAddress;
        
        if (tls_dir_rva + sizeof(TLS_DIRECTORY64) <= size_of_image) {
            // Read TLS directory
            TLS_DIRECTORY64 tls_dir;
            uc_err_code = uc_mem_read(ctx->uc, image_base + tls_dir_rva, &tls_dir, sizeof(tls_dir));
            
            if (uc_err_code == UC_ERR_OK) {
                // Map TLS storage region (64KB)
                err = ctx->mem->map(TLS_STORAGE_BASE, 0x10000, UC_PROT_READ | UC_PROT_WRITE, "TLS_STORAGE");
                if (err == ELIXIR_OK) {
                    // Copy TLS data template if present
                    if (tls_dir.StartAddressOfRawData != 0 && tls_dir.EndAddressOfRawData > tls_dir.StartAddressOfRawData) {
                        uint64_t tls_data_size = tls_dir.EndAddressOfRawData - tls_dir.StartAddressOfRawData;
                        if (tls_data_size > 0 && tls_data_size <= 0x10000) {
                            // Read from emulated memory and write to TLS storage
                            std::vector<uint8_t> tls_data(tls_data_size);
                            uc_mem_read(ctx->uc, tls_dir.StartAddressOfRawData, tls_data.data(), tls_data_size);
                            uc_mem_write(ctx->uc, TLS_STORAGE_BASE, tls_data.data(), tls_data_size);
                        }
                    }
                }
                
                // Map TLS vector region (64KB)
                ctx->mem->map(TLS_VECTOR_ADDRESS, 0x10000, UC_PROT_READ | UC_PROT_WRITE, "TLS_VECTOR");
            }
        }
    }
    
    return ELIXIR_OK;
}
