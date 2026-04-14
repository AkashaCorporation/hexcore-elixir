// HexCore Elixir — Linux Kernel API Stub Implementation
//
// Clean-room implementation for Linux kernel module emulation.
// Provides stub handlers for external kernel symbols (kmalloc, memcpy, etc.)
//
// Apache-2.0 licensed. No code copied verbatim.

#include "elixir/linux_stubs.h"
#include "elixir/engine_internal.h"
#include "elixir/memory_manager.h"
#include <unicorn/x86.h>
#include <cstring>
#include <cstdio>

LinuxKernelStubs::LinuxKernelStubs(uc_engine* uc, MemoryManager* mem, ElixirContext* ctx)
    : uc_(uc), mem_(mem), ctx_(ctx), next_stub_addr_(LINUX_STUB_BASE) {
    
    // Map the stub region (RX only)
    uc_mem_map(uc_, LINUX_STUB_BASE, LINUX_STUB_SIZE, UC_PROT_READ | UC_PROT_EXEC);
    
    // Map kernel heap region for kmalloc simulation
    uc_mem_map(uc_, KERNEL_HEAP_BASE, KERNEL_HEAP_SIZE, UC_PROT_READ | UC_PROT_WRITE);
    kernel_heap_base_ = KERNEL_HEAP_BASE;
    kernel_heap_size_ = KERNEL_HEAP_SIZE;
    next_kmalloc_addr_ = KERNEL_HEAP_BASE;
    
    // Install code hook on the stub region
    uc_hook_add(uc_, &code_hook_handle_, UC_HOOK_CODE,
                (void*)code_hook_callback, this,
                LINUX_STUB_BASE, LINUX_STUB_BASE + LINUX_STUB_SIZE);
    
    // Register built-in handlers
    register_builtin_handlers();
}

LinuxKernelStubs::~LinuxKernelStubs() {
    if (code_hook_handle_ && uc_) {
        uc_hook_del(uc_, code_hook_handle_);
    }
}

uint64_t LinuxKernelStubs::read_reg(int regid) {
    uint64_t val = 0;
    uc_reg_read(uc_, regid, &val);
    return val;
}

void LinuxKernelStubs::write_reg(int regid, uint64_t value) {
    uc_reg_write(uc_, regid, &value);
}

void LinuxKernelStubs::do_return(uint64_t retval) {
    // Write return value to RAX
    write_reg(UC_X86_REG_RAX, retval);
    // Pop return address: read [rsp], set RIP, rsp += 8
    uint64_t rsp = read_reg(UC_X86_REG_RSP);
    uint64_t ret_addr = 0;
    uc_mem_read(uc_, rsp, &ret_addr, 8);
    write_reg(UC_X86_REG_RIP, ret_addr);
    write_reg(UC_X86_REG_RSP, rsp + 8);
}

std::vector<uint64_t> LinuxKernelStubs::read_args_sysv(int count) {
    // System V AMD64 ABI: RDI, RSI, RDX, RCX, R8, R9
    // Stack args start at [rsp+8] (after return address)
    std::vector<uint64_t> args;
    if (count > 0) args.push_back(read_reg(UC_X86_REG_RDI));
    if (count > 1) args.push_back(read_reg(UC_X86_REG_RSI));
    if (count > 2) args.push_back(read_reg(UC_X86_REG_RDX));
    if (count > 3) args.push_back(read_reg(UC_X86_REG_RCX));
    if (count > 4) args.push_back(read_reg(UC_X86_REG_R8));
    if (count > 5) args.push_back(read_reg(UC_X86_REG_R9));
    
    // Stack arguments
    uint64_t rsp = read_reg(UC_X86_REG_RSP);
    for (int i = 6; i < count; i++) {
        uint64_t val = 0;
        uc_mem_read(uc_, rsp + 8 + (i - 6) * 8, &val, 8);
        args.push_back(val);
    }
    return args;
}

void LinuxKernelStubs::code_hook_callback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    (void)size;
    auto* self = static_cast<LinuxKernelStubs*>(user_data);
    
    auto it = self->handlers_.find(address);
    if (it == self->handlers_.end()) {
        return;  // No handler, let the RET stub execute
    }
    
    // Read arguments using SysV ABI
    auto args = self->read_args_sysv(6);
    
    // Call handler
    uint64_t result = it->second(self->uc_, self->mem_, args);
    
    // Return from function call
    self->do_return(result);
    
    (void)args;  // suppress unused warning
}

void LinuxKernelStubs::register_handler(const std::string& name, uint64_t stub_addr, LinuxKernelHandler handler) {
    handlers_[stub_addr] = handler;
    stub_to_name_[stub_addr] = name;
}

uint64_t LinuxKernelStubs::alloc_stub(const std::string& name, LinuxKernelHandler handler) {
    if (next_stub_addr_ >= LINUX_STUB_BASE + LINUX_STUB_SIZE - 16) {
        return 0;  // Out of stub space
    }
    
    uint64_t addr = next_stub_addr_;
    next_stub_addr_ += 16;  // 16-byte aligned
    
    // Write RET instruction (0xC3)
    uint8_t ret_insn = 0xC3;
    uc_mem_write(uc_, addr, &ret_insn, 1);
    
    if (handler) {
        register_handler(name, addr, handler);
    } else {
        stub_to_name_[addr] = name;
    }
    
    return addr;
}

uint64_t LinuxKernelStubs::alloc_ret_stub(const std::string& name) {
    // XOR EAX,EAX; RET (0x31 0xC0 0xC3) - returns 0
    if (next_stub_addr_ >= LINUX_STUB_BASE + LINUX_STUB_SIZE - 16) {
        return 0;
    }
    
    uint64_t addr = next_stub_addr_;
    next_stub_addr_ += 16;
    
    uint8_t code[] = { 0x31, 0xC0, 0xC3 };  // xor eax, eax; ret
    uc_mem_write(uc_, addr, code, sizeof(code));
    
    stub_to_name_[addr] = name;
    return addr;
}

uint64_t LinuxKernelStubs::get_stub_addr(const std::string& name) const {
    for (const auto& [addr, n] : stub_to_name_) {
        if (n == name) return addr;
    }
    return 0;
}

uint64_t LinuxKernelStubs::kmalloc(uint64_t size, uint32_t flags) {
    (void)flags;  // Ignore flags for now
    
    // Align size to 8 bytes
    size = (size + 7) & ~7ULL;
    
    if (next_kmalloc_addr_ + size > kernel_heap_base_ + kernel_heap_size_) {
        return 0;  // Out of memory
    }
    
    uint64_t addr = next_kmalloc_addr_;
    next_kmalloc_addr_ += size;
    kmalloc_allocs_[addr] = size;
    
    // Zero the memory (GFP_ZERO behavior)
    std::vector<uint8_t> zeros(size, 0);
    uc_mem_write(uc_, addr, zeros.data(), size);
    
    return addr;
}

void LinuxKernelStubs::kfree(uint64_t addr) {
    auto it = kmalloc_allocs_.find(addr);
    if (it != kmalloc_allocs_.end()) {
        kmalloc_allocs_.erase(it);
    }
}

// Built-in handler implementations

uint64_t LinuxKernelStubs::handle_kmalloc(uc_engine* uc, MemoryManager* mem, const std::vector<uint64_t>& args) {
    // kmalloc(size_t size, gfp_t flags)
    // args[0] = size, args[1] = flags
    if (args.size() < 1 || args[0] == 0) return 0;
    
    // Use MemoryManager's heap for simplicity
    return mem->heap_alloc(args[0], (args.size() > 1 && args[1] & 0x80000));  // GFP_ZERO = 0x80000
}

uint64_t LinuxKernelStubs::handle_kfree(uc_engine* uc, MemoryManager* mem, const std::vector<uint64_t>& args) {
    // kfree(const void* ptr)
    if (args.size() >= 1 && args[0] != 0) {
        mem->heap_free(args[0]);
    }
    return 0;  // void function
}

uint64_t LinuxKernelStubs::handle_memcpy(uc_engine* uc, MemoryManager* mem, const std::vector<uint64_t>& args) {
    // memcpy(void* dest, const void* src, size_t n)
    if (args.size() < 3 || args[0] == 0) return 0;
    (void)mem;
    
    uint64_t dest = args[0];
    uint64_t src = args[1];
    uint64_t n = args[2];
    
    if (n > 0 && n < 0x10000000) {  // Sanity check
        std::vector<uint8_t> buffer(n);
        uc_mem_read(uc, src, buffer.data(), n);
        uc_mem_write(uc, dest, buffer.data(), n);
    }
    
    return dest;  // Returns dest
}

uint64_t LinuxKernelStubs::handle_memmove(uc_engine* uc, MemoryManager* mem, const std::vector<uint64_t>& args) {
    // memmove(void* dest, const void* src, size_t n)
    if (args.size() < 3 || args[0] == 0) return 0;
    (void)mem;
    
    uint64_t dest = args[0];
    uint64_t src = args[1];
    uint64_t n = args[2];
    
    if (n > 0 && n < 0x10000000) {
        std::vector<uint8_t> buffer(n);
        uc_mem_read(uc, src, buffer.data(), n);
        uc_mem_write(uc, dest, buffer.data(), n);
    }
    
    return dest;
}

uint64_t LinuxKernelStubs::handle_memset(uc_engine* uc, MemoryManager* mem, const std::vector<uint64_t>& args) {
    // memset(void* s, int c, size_t n)
    if (args.size() < 3 || args[0] == 0) return 0;
    (void)mem;
    
    uint64_t s = args[0];
    uint8_t c = static_cast<uint8_t>(args[1]);
    uint64_t n = args[2];
    
    if (n > 0 && n < 0x10000000) {
        std::vector<uint8_t> buffer(n, c);
        uc_mem_write(uc, s, buffer.data(), n);
    }
    
    return s;
}

uint64_t LinuxKernelStubs::handle_memcmp(uc_engine* uc, MemoryManager* mem, const std::vector<uint64_t>& args) {
    // memcmp(const void* s1, const void* s2, size_t n)
    if (args.size() < 3) return 0;
    (void)mem;
    
    uint64_t s1 = args[0];
    uint64_t s2 = args[1];
    uint64_t n = args[2];
    
    for (uint64_t i = 0; i < n; i++) {
        uint8_t b1 = 0, b2 = 0;
        uc_mem_read(uc, s1 + i, &b1, 1);
        uc_mem_read(uc, s2 + i, &b2, 1);
        if (b1 != b2) return (b1 < b2) ? -1 : 1;
    }
    
    return 0;
}

uint64_t LinuxKernelStubs::handle_printk(uc_engine* uc, MemoryManager* mem, const std::vector<uint64_t>& args) {
    // printk(const char* fmt, ...)
    // Just return the format string length for now
    (void)uc;
    (void)mem;
    (void)args;
    return 0;  // Return bytes written (stub)
}

void LinuxKernelStubs::register_builtin_handlers() {
    // Memory allocation family
    alloc_stub("kmalloc", handle_kmalloc);
    alloc_stub("__kmalloc", handle_kmalloc);
    alloc_stub("kzalloc", handle_kmalloc);  // kzalloc = kmalloc + GFP_ZERO
    alloc_stub("vmalloc", handle_kmalloc);
    alloc_stub("kfree", handle_kfree);
    alloc_stub("vfree", handle_kfree);
    
    // Memory operations
    alloc_stub("memcpy", handle_memcpy);
    alloc_stub("__memcpy", handle_memcpy);
    alloc_stub("memmove", handle_memmove);
    alloc_stub("memset", handle_memset);
    alloc_stub("__memset", handle_memset);
    alloc_stub("memcmp", handle_memcmp);
    
    // Printing
    alloc_stub("printk", handle_printk);
    alloc_stub("_printk", handle_printk);
    
    // Locking primitives - just return (no-op)
    // These are void functions or return 0
    alloc_ret_stub("mutex_lock");
    alloc_ret_stub("mutex_unlock");
    alloc_ret_stub("mutex_init");
    alloc_ret_stub("spin_lock");
    alloc_ret_stub("spin_unlock");
    alloc_ret_stub("spin_lock_irqsave");
    alloc_ret_stub("spin_unlock_irqrestore");
    alloc_ret_stub("_raw_spin_lock");
    alloc_ret_stub("_raw_spin_unlock");
    alloc_ret_stub("_raw_spin_lock_irqsave");
    alloc_ret_stub("_raw_spin_unlock_irqrestore");
    
    // RCU - no-op
    alloc_ret_stub("__rcu_read_lock");
    alloc_ret_stub("__rcu_read_unlock");
    alloc_ret_stub("rcu_read_lock");
    alloc_ret_stub("rcu_read_unlock");
    alloc_ret_stub("synchronize_rcu");
    
    // Atomic operations - return 0 (success)
    alloc_ret_stub("atomic_read");
    alloc_ret_stub("atomic_set");
    alloc_ret_stub("atomic_inc");
    alloc_ret_stub("atomic_dec");
    alloc_ret_stub("atomic_add");
    alloc_ret_stub("atomic_sub");
    
    // Wait queues
    alloc_ret_stub("init_waitqueue_head");
    alloc_ret_stub("wake_up");
    alloc_ret_stub("wait_event");
    alloc_ret_stub("wait_event_interruptible");
    
    // Misc kernel functions
    alloc_ret_stub("__init_waitqueue_head");
    alloc_ret_stub("__wake_up");
    alloc_ret_stub("complete");
    alloc_ret_stub("complete_all");
    alloc_ret_stub("wait_for_completion");
    alloc_ret_stub("init_completion");
    
    // String operations (may be implemented as builtins)
    alloc_stub("strlen", [](uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args) -> uint64_t {
        if (args.empty() || args[0] == 0) return 0;
        uint64_t s = args[0];
        uint64_t len = 0;
        while (len < 0x10000) {  // Max 64KB string
            uint8_t c = 0;
            uc_mem_read(uc, s + len, &c, 1);
            if (c == 0) break;
            len++;
        }
        return len;
    });
    
    alloc_stub("strcmp", [](uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args) -> uint64_t {
        if (args.size() < 2 || args[0] == 0 || args[1] == 0) return 1;
        uint64_t s1 = args[0];
        uint64_t s2 = args[1];
        for (uint64_t i = 0; i < 0x10000; i++) {
            uint8_t c1 = 0, c2 = 0;
            uc_mem_read(uc, s1 + i, &c1, 1);
            uc_mem_read(uc, s2 + i, &c2, 1);
            if (c1 != c2) return (c1 < c2) ? -1 : 1;
            if (c1 == 0) return 0;
        }
        return 0;
    });
    
    alloc_stub("strncmp", [](uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args) -> uint64_t {
        if (args.size() < 3 || args[0] == 0 || args[1] == 0) return 1;
        uint64_t s1 = args[0];
        uint64_t s2 = args[1];
        uint64_t n = args[2];
        for (uint64_t i = 0; i < n; i++) {
            uint8_t c1 = 0, c2 = 0;
            uc_mem_read(uc, s1 + i, &c1, 1);
            uc_mem_read(uc, s2 + i, &c2, 1);
            if (c1 != c2) return (c1 < c2) ? -1 : 1;
            if (c1 == 0) return 0;
        }
        return 0;
    });
    
    alloc_stub("strcpy", [](uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args) -> uint64_t {
        if (args.size() < 2 || args[0] == 0 || args[1] == 0) return 0;
        uint64_t dest = args[0];
        uint64_t src = args[1];
        uint64_t i = 0;
        while (i < 0x10000) {
            uint8_t c = 0;
            uc_mem_read(uc, src + i, &c, 1);
            uc_mem_write(uc, dest + i, &c, 1);
            if (c == 0) break;
            i++;
        }
        return dest;
    });
    
    alloc_stub("strncpy", [](uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args) -> uint64_t {
        if (args.size() < 3 || args[0] == 0 || args[1] == 0) return 0;
        uint64_t dest = args[0];
        uint64_t src = args[1];
        uint64_t n = args[2];
        for (uint64_t i = 0; i < n; i++) {
            uint8_t c = 0;
            uc_mem_read(uc, src + i, &c, 1);
            uc_mem_write(uc, dest + i, &c, 1);
        }
        return dest;
    });
    
    alloc_stub("strchr", [](uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args) -> uint64_t {
        if (args.size() < 2 || args[0] == 0) return 0;
        uint64_t s = args[0];
        uint8_t c = static_cast<uint8_t>(args[1]);
        for (uint64_t i = 0; i < 0x10000; i++) {
            uint8_t ch = 0;
            uc_mem_read(uc, s + i, &ch, 1);
            if (ch == c) return s + i;
            if (ch == 0) break;
        }
        return 0;
    });
    
    // Misc
    alloc_stub("snprintf", [](uc_engine*, MemoryManager*, const std::vector<uint64_t>& args) -> uint64_t {
        if (args.size() < 2) return 0;
        // Just return 0 (nothing written)
        return 0;
    });
    
    alloc_stub("sprintf", [](uc_engine*, MemoryManager*, const std::vector<uint64_t>& args) -> uint64_t {
        if (args.empty()) return 0;
        return 0;
    });
}
