// HexCore Elixir — Linux Kernel API Stub Table
//
// Clean-room implementation for Linux kernel module emulation.
// Provides stub handlers for external kernel symbols (kmalloc, memcpy, etc.)
//
// Apache-2.0 licensed. No code copied verbatim.

#pragma once

#include "elixir.h"
#include <cstdint>
#include <string>
#include <map>
#include <unordered_map>
#include <vector>
#include <functional>
#include <unicorn/unicorn.h>

class MemoryManager;
struct ElixirContext;

// Handler function type for Linux kernel stubs
using LinuxKernelHandler = std::function<uint64_t(uc_engine*, MemoryManager*, const std::vector<uint64_t>&)>;

// Linux kernel symbol information
struct LinuxKernelSymbol {
    std::string name;
    uint64_t stub_addr;
    LinuxKernelHandler handler;
    bool needs_hook;  // true if needs UC_HOOK_CODE, false for simple RET stub
};

class LinuxKernelStubs {
    uc_engine* uc_;
    MemoryManager* mem_;
    ElixirContext* ctx_ = nullptr;
    uc_hook code_hook_handle_ = 0;
    
    // Handler dispatch
    std::map<uint64_t, LinuxKernelHandler> handlers_;
    std::map<uint64_t, std::string> stub_to_name_;
    
    // Stub allocation
    uint64_t next_stub_addr_;
    
    // Heap for kmalloc simulation
    uint64_t kernel_heap_base_ = 0;
    uint64_t kernel_heap_size_ = 0;
    std::map<uint64_t, uint64_t> kmalloc_allocs_;  // addr -> size
    uint64_t next_kmalloc_addr_ = 0;
    
    // Static callback for Unicorn hook
    static void code_hook_callback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    
    // Internal helpers
    uint64_t read_reg(int regid);
    void write_reg(int regid, uint64_t value);
    void do_return(uint64_t retval);
    std::vector<uint64_t> read_args_sysv(int count);  // SysV ABI: RDI, RSI, RDX, RCX, R8, R9
    
    // Built-in handlers
    static uint64_t handle_kmalloc(uc_engine* uc, MemoryManager* mem, const std::vector<uint64_t>& args);
    static uint64_t handle_kfree(uc_engine* uc, MemoryManager* mem, const std::vector<uint64_t>& args);
    static uint64_t handle_memcpy(uc_engine* uc, MemoryManager* mem, const std::vector<uint64_t>& args);
    static uint64_t handle_memmove(uc_engine* uc, MemoryManager* mem, const std::vector<uint64_t>& args);
    static uint64_t handle_memset(uc_engine* uc, MemoryManager* mem, const std::vector<uint64_t>& args);
    static uint64_t handle_memcmp(uc_engine* uc, MemoryManager* mem, const std::vector<uint64_t>& args);
    static uint64_t handle_printk(uc_engine* uc, MemoryManager* mem, const std::vector<uint64_t>& args);
    
public:
    // LINUX_STUB_BASE = 0x20000000 (close to ETREL_BASE 0x10000000 for 32-bit relative calls)
    // Must be within ±2GB of ETREL_BASE for R_X86_64_PC32/PLT32 relocations
    static constexpr uint64_t LINUX_STUB_BASE = 0x20000000;
    static constexpr uint64_t LINUX_STUB_SIZE = 0x100000;  // 1 MB
    static constexpr uint64_t KERNEL_HEAP_BASE = 0x21000000;
    static constexpr uint64_t KERNEL_HEAP_SIZE = 0x1000000;  // 16 MB
    
    LinuxKernelStubs(uc_engine* uc, MemoryManager* mem, ElixirContext* ctx = nullptr);
    ~LinuxKernelStubs();
    
    void set_context(ElixirContext* ctx) { ctx_ = ctx; }
    
    // Register a handler for a kernel symbol
    void register_handler(const std::string& name, uint64_t stub_addr, LinuxKernelHandler handler);
    
    // Allocate a stub address and optionally register a handler
    uint64_t alloc_stub(const std::string& name, LinuxKernelHandler handler = nullptr);
    
    // Allocate a simple RET stub (returns 0)
    uint64_t alloc_ret_stub(const std::string& name);
    
    // Register all built-in handlers
    void register_builtin_handlers();
    
    // Get stub address by name (for symbol resolution)
    uint64_t get_stub_addr(const std::string& name) const;
    
    // Kernel heap simulation (for kmalloc)
    uint64_t kmalloc(uint64_t size, uint32_t flags = 0);
    void kfree(uint64_t addr);
};
