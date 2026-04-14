// HexCore Elixir — ELF64 Loader
//
// Clean-room implementation using:
//   - ELF specification (Tool Interface Standard)
//   - Linux ABI specification (stack layout)
//
// Apache-2.0 licensed. No code copied verbatim.

#include "elixir/engine_internal.h"
#include "elixir/linux_stubs.h"
#include <cstring>
#include <vector>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <tuple>

// ELF64 structures (inline definitions, no system headers)
#pragma pack(push, 1)

struct Elf64_Ehdr {
    uint8_t  e_ident[16];     // Magic + class + data + version + OS/ABI
    uint16_t e_type;          // ET_EXEC=2, ET_DYN=3, ET_REL=1
    uint16_t e_machine;       // EM_X86_64=62
    uint32_t e_version;
    uint64_t e_entry;         // Entry point
    uint64_t e_phoff;         // Program header table offset
    uint64_t e_shoff;         // Section header table offset
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;         // Number of program headers
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64_Phdr {
    uint32_t p_type;          // PT_LOAD=1, PT_DYNAMIC=2, PT_TLS=7
    uint32_t p_flags;         // PF_X=1, PF_W=2, PF_R=4
    uint64_t p_offset;        // Offset in file
    uint64_t p_vaddr;         // Virtual address
    uint64_t p_paddr;         // Physical address (ignored)
    uint64_t p_filesz;        // Size in file
    uint64_t p_memsz;         // Size in memory (may be > filesz for BSS)
    uint64_t p_align;         // Alignment
};

#pragma pack(pop)

// ET_REL specific structures
struct Elf64_Shdr {
    uint32_t sh_name;      // offset into .shstrtab
    uint32_t sh_type;      // SHT_PROGBITS=1, SHT_SYMTAB=2, SHT_STRTAB=3, SHT_RELA=4, SHT_NOBITS=8
    uint64_t sh_flags;     // SHF_ALLOC=0x2, SHF_EXECINSTR=0x4, SHF_WRITE=0x1
    uint64_t sh_addr;      // 0 for ET_REL (will be assigned)
    uint64_t sh_offset;    // offset in file
    uint64_t sh_size;
    uint32_t sh_link;      // for RELA: index of associated symtab
    uint32_t sh_info;      // for RELA: index of section to apply to
    uint64_t sh_addralign;
    uint64_t sh_entsize;   // for SYMTAB: sizeof(Elf64_Sym)=24, for RELA: sizeof(Elf64_Rela)=24
};

struct Elf64_Sym {
    uint32_t st_name;   // offset into strtab
    uint8_t  st_info;   // ELF64_ST_TYPE (low 4 bits), ELF64_ST_BIND (high 4 bits)
    uint8_t  st_other;
    uint16_t st_shndx;  // SHN_UNDEF=0 means external
    uint64_t st_value;  // offset within section
    uint64_t st_size;
};

struct Elf64_Rela {
    uint64_t r_offset;   // offset within target section
    uint64_t r_info;     // sym_index = r_info >> 32, type = r_info & 0xFFFFFFFF
    int64_t  r_addend;
};

#pragma pack(pop)

// ELF constants
constexpr uint8_t ELFMAG0 = 0x7F;
constexpr uint8_t ELFMAG1 = 'E';
constexpr uint8_t ELFMAG2 = 'L';
constexpr uint8_t ELFMAG3 = 'F';
constexpr uint8_t ELFCLASS64 = 2;
constexpr uint8_t ELFDATA2LSB = 1;  // Little endian
constexpr uint16_t EM_X86_64 = 62;

constexpr uint32_t PT_LOAD = 1;
constexpr uint32_t PF_X = 1;
constexpr uint32_t PF_W = 2;
constexpr uint32_t PF_R = 4;

constexpr uint64_t ELF_STACK_BASE = 0x7FFF0000;
constexpr uint64_t ELF_STACK_SIZE = 0x100000; // 1 MB

// ET_REL constants
constexpr uint16_t ET_REL = 1;      // Relocatable file
constexpr uint16_t ET_EXEC = 2;    // Executable file
constexpr uint16_t ET_DYN = 3;     // Shared object file

// Section header types
constexpr uint32_t SHT_NULL = 0;
constexpr uint32_t SHT_PROGBITS = 1;
constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint32_t SHT_STRTAB = 3;
constexpr uint32_t SHT_RELA = 4;
constexpr uint32_t SHT_NOBITS = 8;

// Section header flags
constexpr uint64_t SHF_WRITE = 0x1;
constexpr uint64_t SHF_ALLOC = 0x2;
constexpr uint64_t SHF_EXECINSTR = 0x4;

// Symbol table
constexpr uint16_t SHN_UNDEF = 0;
constexpr uint8_t STT_FUNC = 2;
constexpr uint8_t STB_GLOBAL = 1;
constexpr uint8_t STB_WEAK = 2;

// Relocation types (x86_64)
constexpr uint32_t R_X86_64_NONE = 0;
constexpr uint32_t R_X86_64_64 = 1;
constexpr uint32_t R_X86_64_PC32 = 2;
constexpr uint32_t R_X86_64_PLT32 = 4;
constexpr uint32_t R_X86_64_32 = 10;
constexpr uint32_t R_X86_64_32S = 11;

// ET_REL base address (after heap at 0x10000000 and after Linux stubs at 0x20000000)
// This ensures no conflict with heap and stays within 32-bit relative call range of stubs
constexpr uint64_t ETREL_BASE = 0x30000000;



static uint64_t align_down(uint64_t value, uint64_t alignment) {
    return value & ~(alignment - 1);
}

static uint64_t align_up(uint64_t value, uint64_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

// Helper to read a string from the file data
static std::string read_string(const uint8_t* data, uint64_t len, uint64_t offset) {
    if (offset >= len) return "";
    std::string result;
    while (offset < len && data[offset] != 0) {
        result += static_cast<char>(data[offset++]);
    }
    return result;
}

// ET_REL loader for kernel modules (.ko files)
static ElixirError elf_load_relocatable(ElixirContext* ctx, const uint8_t* data, uint64_t len, uint64_t* entry_point) {
    const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr*>(data);
    const uint64_t page_size = 0x1000;
    
    // Step 1: Validate section header info
    if (ehdr->e_shnum == 0 || ehdr->e_shentsize < sizeof(Elf64_Shdr)) {
        return ELIXIR_ERR_LOADER;
    }
    
    uint64_t shoff = ehdr->e_shoff;
    if (shoff > len || shoff + (uint64_t)ehdr->e_shnum * ehdr->e_shentsize > len) {
        return ELIXIR_ERR_LOADER;
    }
    
    // Read section headers
    std::vector<Elf64_Shdr> shdrs(ehdr->e_shnum);
    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        const uint8_t* shdr_ptr = data + shoff + (uint64_t)i * ehdr->e_shentsize;
        const Elf64_Shdr* src = reinterpret_cast<const Elf64_Shdr*>(shdr_ptr);
        shdrs[i] = *src;
    }
    
    // Read .shstrtab (section header string table)
    if (ehdr->e_shstrndx >= shdrs.size()) {
        return ELIXIR_ERR_LOADER;
    }
    const Elf64_Shdr& shstrtab = shdrs[ehdr->e_shstrndx];
    if (shstrtab.sh_offset > len || shstrtab.sh_offset + shstrtab.sh_size > len) {
        return ELIXIR_ERR_LOADER;
    }
    const uint8_t* shstrtab_data = data + shstrtab.sh_offset;
    uint64_t shstrtab_size = shstrtab.sh_size;
    
    // Helper to get section name
    auto get_section_name = [&](uint32_t name_offset) -> std::string {
        return read_string(shstrtab_data, shstrtab_size, name_offset);
    };
    
    // Step 2: Calculate layout for allocatable sections
    std::vector<uint64_t> section_addr(shdrs.size(), 0);
    uint64_t current_offset = 0;
    
    for (size_t i = 0; i < shdrs.size(); i++) {
        const Elf64_Shdr& shdr = shdrs[i];
        
        // Only process allocatable sections
        if (!(shdr.sh_flags & SHF_ALLOC)) {
            continue;
        }
        
        // Align to section alignment
        uint64_t align = shdr.sh_addralign > 1 ? shdr.sh_addralign : 1;
        current_offset = align_up(current_offset, align);
        
        section_addr[i] = ETREL_BASE + current_offset;
        current_offset += shdr.sh_size;
    }
    
    // Step 3: Map all ALLOC sections into Unicorn
    // First pass: find contiguous ranges of ALLOC sections
    std::vector<std::tuple<uint64_t, uint64_t, uint32_t>> ranges;
    
    for (size_t i = 0; i < shdrs.size(); i++) {
        const Elf64_Shdr& shdr = shdrs[i];
        
        if (!(shdr.sh_flags & SHF_ALLOC)) {
            continue;
        }
        
        uint64_t addr = section_addr[i];
        uint64_t size = shdr.sh_size;
        if (size == 0) continue;
        
        // Calculate protection flags - use RWX for all sections
        uint32_t prot = UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC;
        
        // Page-align for mapping
        uint64_t aligned_addr = align_down(addr, page_size);
        uint64_t aligned_end = align_up(addr + size, page_size);
        
        // Merge with previous range if overlapping or adjacent
        if (!ranges.empty()) {
            auto& [prev_start, prev_end, prev_prot] = ranges.back();
            if (aligned_addr <= prev_end) {
                // Overlapping or adjacent - merge
                prev_end = std::max(prev_end, aligned_end);
                // Already using RWX for everything
                continue;
            }
        }
        
        ranges.push_back(std::make_tuple(aligned_addr, aligned_end, prot));
    }
    
    // Second pass: map the ranges (use smaller chunks if needed)
    for (const auto& [aligned_addr, aligned_end, prot] : ranges) {
        uint64_t aligned_size = aligned_end - aligned_addr;
        
        // Try to map via MemoryManager first
        ElixirError err = ctx->mem->map(aligned_addr, aligned_size, prot, "et_rel");
        if (err != ELIXIR_OK) {
            // Try direct uc_mem_map
            uc_err uc_err = uc_mem_map(ctx->uc, aligned_addr, aligned_size, prot);
            if (uc_err != UC_ERR_OK) {
                // Try mapping in smaller chunks (64KB at a time)
                const uint64_t chunk_size = 0x10000;
                for (uint64_t off = 0; off < aligned_size; off += chunk_size) {
                    uint64_t chunk_addr = aligned_addr + off;
                    uint64_t this_size = std::min(chunk_size, aligned_size - off);
                    uc_err = uc_mem_map(ctx->uc, chunk_addr, this_size, prot);
                    if (uc_err != UC_ERR_OK && uc_err != UC_ERR_MAP) {
                        // UC_ERR_MAP means already mapped - that's OK
                        printf("[ET_REL] Failed to map chunk [0x%llx, 0x%llx): %d\n",
                               (unsigned long long)chunk_addr, 
                               (unsigned long long)(chunk_addr + this_size), uc_err);
                    }
                }
            }
        }
    }
    
    // Third pass: write section data
    for (size_t i = 0; i < shdrs.size(); i++) {
        const Elf64_Shdr& shdr = shdrs[i];
        
        if (!(shdr.sh_flags & SHF_ALLOC)) {
            continue;
        }
        
        uint64_t addr = section_addr[i];
        uint64_t size = shdr.sh_size;
        if (size == 0) continue;
        
        // Debug: print section info
        std::string sec_name = get_section_name(shdr.sh_name);
        printf("[ET_REL] Section %zu: '%s' addr=0x%llx size=0x%llx flags=0x%x type=%u\n",
               i, sec_name.c_str(), (unsigned long long)addr, (unsigned long long)size,
               (unsigned)shdr.sh_flags, shdr.sh_type);
        
        // Write section data (for all ALLOC sections except NOBITS which is zero-filled)
        if (shdr.sh_type != SHT_NOBITS && shdr.sh_offset < len) {
            uint64_t write_size = std::min(shdr.sh_size, len - shdr.sh_offset);
            uc_mem_write(ctx->uc, addr, data + shdr.sh_offset, write_size);
        }
    }
    
    uint64_t last_mapped_end = ranges.empty() ? ETREL_BASE : std::get<1>(ranges.back());
    
    // Step 4: Read symbol table
    int64_t symtab_idx = -1;
    for (size_t i = 0; i < shdrs.size(); i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab_idx = static_cast<int64_t>(i);
            break;
        }
    }
    
    if (symtab_idx < 0) {
        return ELIXIR_ERR_LOADER;  // No symbol table
    }
    
    const Elf64_Shdr& symtab_shdr = shdrs[symtab_idx];
    const uint8_t* symtab_data = data + symtab_shdr.sh_offset;
    uint64_t symtab_size = symtab_shdr.sh_size;
    
    // Read associated string table
    if (symtab_shdr.sh_link >= shdrs.size()) {
        return ELIXIR_ERR_LOADER;
    }
    const Elf64_Shdr& strtab_shdr = shdrs[symtab_shdr.sh_link];
    const uint8_t* strtab_data = data + strtab_shdr.sh_offset;
    uint64_t strtab_size = strtab_shdr.sh_size;
    
    // Parse symbols
    uint64_t num_syms = symtab_size / sizeof(Elf64_Sym);
    std::vector<uint64_t> sym_addr(num_syms, 0);
    std::vector<std::string> sym_names(num_syms);
    
    // Create Linux kernel stubs
    auto linux_stubs = std::make_unique<LinuxKernelStubs>(ctx->uc, ctx->mem.get(), ctx);
    
    for (uint64_t i = 0; i < num_syms; i++) {
        const Elf64_Sym* sym = reinterpret_cast<const Elf64_Sym*>(symtab_data + i * sizeof(Elf64_Sym));
        sym_names[i] = read_string(strtab_data, strtab_size, sym->st_name);
        
        if (sym->st_shndx == SHN_UNDEF) {
            // External symbol - needs stub
            if (sym->st_name != 0 && !sym_names[i].empty()) {
                // Check if we already have a stub for this symbol
                uint64_t stub = linux_stubs->get_stub_addr(sym_names[i]);
                if (stub == 0) {
                    // Allocate a simple RET stub (returns 0)
                    stub = linux_stubs->alloc_ret_stub(sym_names[i]);
                }
                sym_addr[i] = stub;
                
                // Store as import for logging
                ImportEntry imp;
                imp.dll_name = "kernel";
                imp.func_name = sym_names[i];
                imp.stub_addr = stub;
                imp.is_data_import = false;
                ctx->imports.push_back(imp);
            }
        } else if (sym->st_shndx < shdrs.size()) {
            // Resolved symbol
            sym_addr[i] = section_addr[sym->st_shndx] + sym->st_value;
        }
    }
    
    // Step 5: Apply relocations
    for (size_t i = 0; i < shdrs.size(); i++) {
        const Elf64_Shdr& shdr = shdrs[i];
        
        if (shdr.sh_type != SHT_RELA) {
            continue;
        }
        
        // Get target section
        if (shdr.sh_info >= shdrs.size()) continue;
        const Elf64_Shdr& target_shdr = shdrs[shdr.sh_info];
        
        // Skip debug sections (huge amount of relocations)
        std::string target_name = get_section_name(target_shdr.sh_name);
        if (target_name.find(".debug") == 0 || target_name.find(".eh_frame") == 0) {
            continue;
        }
        
        // Skip non-allocatable sections
        if (!(target_shdr.sh_flags & SHF_ALLOC)) {
            continue;
        }
        
        uint64_t target_base = section_addr[shdr.sh_info];
        if (target_base == 0) continue;
        
        // Process relocations
        const uint8_t* rela_data = data + shdr.sh_offset;
        uint64_t rela_count = shdr.sh_size / sizeof(Elf64_Rela);
        
        printf("[ET_REL] Processing %llu relocations for section '%s' (target base 0x%llx)\n",
               (unsigned long long)rela_count, target_name.c_str(), (unsigned long long)target_base);
        
        int unhandled_count = 0;
        for (uint64_t j = 0; j < rela_count; j++) {
            const Elf64_Rela* rela = reinterpret_cast<const Elf64_Rela*>(rela_data + j * sizeof(Elf64_Rela));
            
            uint32_t type = static_cast<uint32_t>(rela->r_info & 0xFFFFFFFF);
            uint64_t sym_idx = rela->r_info >> 32;
            
            if (type == R_X86_64_NONE) continue;
            
            if (sym_idx >= num_syms) continue;
            
            uint64_t S = sym_addr[sym_idx];
            int64_t A = rela->r_addend;
            uint64_t P = target_base + rela->r_offset;
            
            // Debug: show relocation details for .init.text
            if (target_name == ".init.text" && j < 15) {
                printf("[ET_REL] Reloc %llu: type=%u sym=%llu S=0x%llx A=0x%llx P=0x%llx\n",
                       (unsigned long long)j, type, (unsigned long long)sym_idx,
                       (unsigned long long)S, (long long)A, (unsigned long long)P);
            }
            
            switch (type) {
                case R_X86_64_64: {
                    uint64_t val = S + A;
                    uc_mem_write(ctx->uc, P, &val, 8);
                    break;
                }
                case R_X86_64_PC32:
                case R_X86_64_PLT32: {
                    int32_t val = static_cast<int32_t>(S + A - P);
                    uc_mem_write(ctx->uc, P, &val, 4);
                    break;
                }
                case R_X86_64_32: {
                    uint32_t val = static_cast<uint32_t>(S + A);
                    uc_mem_write(ctx->uc, P, &val, 4);
                    break;
                }
                case R_X86_64_32S: {
                    int32_t val = static_cast<int32_t>(S + A);
                    uc_mem_write(ctx->uc, P, &val, 4);
                    break;
                }
                default:
                    // Unknown relocation type - count and skip
                    if (unhandled_count < 5) {
                        printf("[ET_REL] Unhandled relocation type %u at offset 0x%llx\n",
                               type, (unsigned long long)rela->r_offset);
                    }
                    unhandled_count++;
                    break;
            }
        }
        if (unhandled_count > 0) {
            printf("[ET_REL] Warning: %d unhandled relocations in section '%s'\n", 
                   unhandled_count, target_name.c_str());
        }
    }
    
    // Step 6: Find entry point (kbase_jit_allocate for mali_kbase.ko)
    uint64_t entry = 0;
    for (uint64_t i = 0; i < num_syms; i++) {
        const Elf64_Sym* sym = reinterpret_cast<const Elf64_Sym*>(symtab_data + i * sizeof(Elf64_Sym));
        
        // Look for kbase_jit_allocate or init_module
        if (sym_names[i] == "kbase_jit_allocate" || sym_names[i] == "init_module") {
            entry = sym_addr[i];
            printf("[ET_REL] Found entry point '%s' at 0x%llx (section %u, offset 0x%llx)\n",
                   sym_names[i].c_str(), (unsigned long long)entry,
                   sym->st_shndx, (unsigned long long)sym->st_value);
            break;
        }
        
        // Fallback to first executable section
        if (entry == 0 && (sym->st_info & 0xF) == STT_FUNC && sym->st_shndx != SHN_UNDEF) {
            entry = sym_addr[i];
        }
    }
    
    printf("[ET_REL] Entry point = 0x%llx, mapped range = 0x%llx - 0x%llx\n",
           (unsigned long long)entry, (unsigned long long)ETREL_BASE, 
           (unsigned long long)last_mapped_end);
    
    // Debug: dump first 16 bytes at entry point
    if (entry >= ETREL_BASE && entry < last_mapped_end) {
        uint8_t buf[16] = {0};
        uc_mem_read(ctx->uc, entry, buf, 16);
        printf("[ET_REL] Bytes at entry point: ");
        for (int j = 0; j < 16; j++) {
            printf("%02x ", buf[j]);
        }
        printf("\n");
    } else {
        printf("[ET_REL] WARNING: Entry point outside mapped range!\n");
    }

    *entry_point = entry;
    
    // Step 7: Setup stack for kernel module
    ElixirError err = ctx->mem->map(ELF_STACK_BASE, ELF_STACK_SIZE,
                                     UC_PROT_READ | UC_PROT_WRITE, "stack");
    if (err != ELIXIR_OK) {
        return err;
    }
    
    // Store linux_stubs in context so it persists during execution
    ctx->linux_stubs = std::move(linux_stubs);
    
    return ELIXIR_OK;
}

ElixirError elf_load(ElixirContext* ctx, const uint8_t* data, uint64_t len, uint64_t* entry_point) {
    if (!ctx || !ctx->uc || !ctx->mem || !data || len == 0 || !entry_point) {
        return ELIXIR_ERR_ARGS;
    }

    // A. Header validation
    if (len < sizeof(Elf64_Ehdr)) {
        return ELIXIR_ERR_LOADER;
    }

    const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr*>(data);

    // Check magic: {0x7F, 'E', 'L', 'F'}
    if (ehdr->e_ident[0] != ELFMAG0 || ehdr->e_ident[1] != ELFMAG1 ||
        ehdr->e_ident[2] != ELFMAG2 || ehdr->e_ident[3] != ELFMAG3) {
        return ELIXIR_ERR_LOADER;
    }

    // Check class: ELFCLASS64 (2)
    if (ehdr->e_ident[4] != ELFCLASS64) {
        return ELIXIR_ERR_LOADER;
    }

    // Check data encoding: ELFDATA2LSB (1, little endian)
    if (ehdr->e_ident[5] != ELFDATA2LSB) {
        return ELIXIR_ERR_LOADER;
    }

    // Check machine: EM_X86_64 (62)
    if (ehdr->e_machine != EM_X86_64) {
        return ELIXIR_ERR_LOADER;
    }
    
    // Check file type and dispatch to appropriate loader
    if (ehdr->e_type == ET_REL) {
        return elf_load_relocatable(ctx, data, len, entry_point);
    }
    
    // ET_EXEC and ET_DYN continue with existing code

    // Validate program header info (only for ET_EXEC/ET_DYN)
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        return ELIXIR_ERR_LOADER;
    }
    
    if (ehdr->e_phnum == 0 || ehdr->e_phentsize < sizeof(Elf64_Phdr)) {
        return ELIXIR_ERR_LOADER;
    }

    // Check that program headers fit in the file (overflow-safe)
    uint64_t phoff = ehdr->e_phoff;
    uint64_t phnum = ehdr->e_phnum;
    uint64_t phentsize = ehdr->e_phentsize;

    if (phoff > len) {
        return ELIXIR_ERR_LOADER;
    }
    uint64_t ph_table_size = phnum * phentsize;
    if (ph_table_size > len - phoff) {
        return ELIXIR_ERR_LOADER;
    }

    // B. Map PT_LOAD segments
    const uint64_t page_size = 0x1000;

    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        const uint8_t* phdr_ptr = data + ehdr->e_phoff + (uint64_t)i * ehdr->e_phentsize;
        const Elf64_Phdr* phdr = reinterpret_cast<const Elf64_Phdr*>(phdr_ptr);

        // Only process PT_LOAD segments
        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        // Skip zero-size segments
        if (phdr->p_memsz == 0) {
            continue;
        }

        // Convert flags: PF_R(4)->UC_PROT_READ, PF_W(2)->UC_PROT_WRITE, PF_X(1)->UC_PROT_EXEC
        uint32_t prot = 0;
        if (phdr->p_flags & PF_R) prot |= UC_PROT_READ;
        if (phdr->p_flags & PF_W) prot |= UC_PROT_WRITE;
        if (phdr->p_flags & PF_X) prot |= UC_PROT_EXEC;

        // Align addresses to page boundary
        uint64_t aligned_vaddr = align_down(phdr->p_vaddr, page_size);
        uint64_t aligned_memsz = align_up(phdr->p_vaddr + phdr->p_memsz, page_size) - aligned_vaddr;

        // Map the segment
        ElixirError err = ctx->mem->map(aligned_vaddr, aligned_memsz, prot, "elf_segment");
        if (err != ELIXIR_OK) {
            return err;
        }

        // Write file data to memory
        if (phdr->p_filesz > 0) {
            // Calculate offset within the mapped region
            uint64_t offset_in_region = phdr->p_vaddr - aligned_vaddr;
            
            // Ensure we don't read past the file (overflow-safe)
            uint64_t file_offset = phdr->p_offset;
            uint64_t bytes_to_write = phdr->p_filesz;

            if (file_offset > len) {
                continue;
            }
            if (bytes_to_write > len - file_offset) {
                bytes_to_write = len - file_offset;
            }

            if (bytes_to_write > 0) {
                uc_err uc_err_code = uc_mem_write(ctx->uc, phdr->p_vaddr,
                                                   data + file_offset,
                                                   bytes_to_write);
                if (uc_err_code != UC_ERR_OK) {
                    return ELIXIR_ERR_MEMORY;
                }
            }
        }

        // If p_memsz > p_filesz, the extra space is BSS (already zero from mapping)
        // Unicorn's uc_mem_map zeros the memory by default
    }

    // C. Stack setup (basic)
    ElixirError err = ctx->mem->map(ELF_STACK_BASE, ELF_STACK_SIZE, 
                                     UC_PROT_READ | UC_PROT_WRITE, "stack");
    if (err != ELIXIR_OK) {
        return err;
    }

    // Write minimal stack layout at top of stack:
    // argc = 0, argv[0] = NULL, envp[0] = NULL
    uint64_t sp = ELF_STACK_BASE + ELF_STACK_SIZE - 0x100; // Leave some room
    
    // Align stack to 16 bytes (System V AMD64 ABI requirement)
    sp = align_down(sp, 16);

    uint64_t argc = 0;
    uc_err uc_err_code = uc_mem_write(ctx->uc, sp, &argc, sizeof(argc));
    if (uc_err_code != UC_ERR_OK) {
        return ELIXIR_ERR_MEMORY;
    }

    // Write NULL argv terminator after argc
    uint64_t null_ptr = 0;
    uc_err_code = uc_mem_write(ctx->uc, sp + 8, &null_ptr, sizeof(null_ptr));
    if (uc_err_code != UC_ERR_OK) {
        return ELIXIR_ERR_MEMORY;
    }

    // D. Return entry point
    *entry_point = ehdr->e_entry;

    return ELIXIR_OK;
}
