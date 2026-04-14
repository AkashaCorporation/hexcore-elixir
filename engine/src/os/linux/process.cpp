// HexCore Elixir — Linux Process Setup
//
// Sets up the initial Linux process environment:
// - Stack layout (argc, argv, envp, auxiliary vector)
// - brk initialization
// - Thread Local Storage (TLS) via arch_prctl
//
// Reference: Linux x86_64 SysV ABI
//
// Apache-2.0 licensed. No code copied verbatim.

#include "elixir/linux_syscalls.h"
#include "elixir/memory_manager.h"
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

// Stack layout constants (SysV ABI)
// Stack grows downward from STACK_TOP
constexpr uint64_t STACK_TOP  = 0x7FFFFF000000ULL;  // Top of user address space
constexpr uint64_t STACK_SIZE = 0x800000;           // 8 MB stack
constexpr uint64_t STACK_BASE = STACK_TOP - STACK_SIZE;

void setup_linux_process_env(uc_engine* uc, MemoryManager* mem) {
    // 1. Map the stack (8 MB at the top of user address space)
    // Stack grows downward, so we map from STACK_BASE to STACK_TOP
    uc_err err = uc_mem_map(uc, STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK) {
        // Try through MemoryManager
        mem->map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE, "stack");
    } else {
        mem->map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE, "stack");
    }
    
    // 2. Initialize RSP (stack pointer)
    // Leave some space at the top for auxv and other data
    // Align to 16 bytes (SysV ABI requirement)
    uint64_t rsp = STACK_TOP - 0x1000;  // 4KB below top
    rsp &= ~0xFULL;  // 16-byte alignment
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
    
    // 3. Initialize RBP (base pointer) - set to 0
    uint64_t rbp = 0;
    uc_reg_write(uc, UC_X86_REG_RBP, &rbp);
    
    // 4. Set up initial stack contents (SysV ABI)
    // At process entry, the stack looks like:
    //   [rsp]        : argc (8 bytes)
    //   [rsp+8]      : argv[0] pointer (or NULL if no args)
    //   [rsp+16]     : argv[1] pointer
    //   ...
    //   [rsp+N]      : NULL (argv terminator)
    //   [rsp+N+8]    : envp[0] pointer
    //   ...
    //   [rsp+M]      : NULL (envp terminator)
    //   [rsp+M+8]    : auxv[0] (auxiliary vector)
    //   ...
    
    // For minimal emulation, we just set argc=0 and NULL terminators
    uint64_t zero = 0;
    uint64_t stack_ptr = rsp;
    
    // argc = 0
    uc_mem_write(uc, stack_ptr, &zero, 8);
    stack_ptr += 8;
    
    // argv[0] = NULL (no program name)
    uc_mem_write(uc, stack_ptr, &zero, 8);
    stack_ptr += 8;
    
    // argv terminator (NULL)
    uc_mem_write(uc, stack_ptr, &zero, 8);
    stack_ptr += 8;
    
    // envp[0] = NULL (no environment)
    uc_mem_write(uc, stack_ptr, &zero, 8);
    stack_ptr += 8;
    
    // envp terminator (NULL)
    uc_mem_write(uc, stack_ptr, &zero, 8);
    stack_ptr += 8;
    
    // Auxiliary vector terminator (AT_NULL = 0)
    // auxv entries are pairs of (type, value)
    // AT_NULL (type=0, value=0) terminates the auxv
    uc_mem_write(uc, stack_ptr, &zero, 8);  // type = AT_NULL
    stack_ptr += 8;
    uc_mem_write(uc, stack_ptr, &zero, 8);  // value = 0
    stack_ptr += 8;
    
    // 5. Clear other general purpose registers
    // (Not strictly necessary, but good for deterministic behavior)
    uc_reg_write(uc, UC_X86_REG_RAX, &zero);
    uc_reg_write(uc, UC_X86_REG_RBX, &zero);
    uc_reg_write(uc, UC_X86_REG_RCX, &zero);
    uc_reg_write(uc, UC_X86_REG_RDX, &zero);
    uc_reg_write(uc, UC_X86_REG_RSI, &zero);
    uc_reg_write(uc, UC_X86_REG_RDI, &zero);
    uc_reg_write(uc, UC_X86_REG_R8,  &zero);
    uc_reg_write(uc, UC_X86_REG_R9,  &zero);
    uc_reg_write(uc, UC_X86_REG_R10, &zero);
    uc_reg_write(uc, UC_X86_REG_R11, &zero);
    uc_reg_write(uc, UC_X86_REG_R12, &zero);
    uc_reg_write(uc, UC_X86_REG_R13, &zero);
    uc_reg_write(uc, UC_X86_REG_R14, &zero);
    uc_reg_write(uc, UC_X86_REG_R15, &zero);
    
    // 6. Initialize segment registers
    // FS and GS are set to 0 (will be set by arch_prctl if needed)
    uint64_t fs_base = 0;
    uint64_t gs_base = 0;
    uc_reg_write(uc, UC_X86_REG_FS_BASE, &fs_base);
    uc_reg_write(uc, UC_X86_REG_GS_BASE, &gs_base);
}
