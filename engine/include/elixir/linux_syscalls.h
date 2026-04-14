// HexCore Elixir — Linux Syscall Handler
//
// Clean-room implementation of Linux syscall emulation for x86_64.
// Reference: Linux man pages, kernel UAPI headers (license exception for userspace use)
//
// Apache-2.0 licensed. No code copied verbatim.

#pragma once

#include <cstdint>
#include <memory>

// Disable Windows min/max macros before including unicorn headers
#if defined(_WIN32)
    #define NOMINMAX
#endif

#include <unicorn/unicorn.h>

// Linux errno values for syscall returns
// Use as -LINUX_EINVAL in return values
constexpr int64_t LINUX_ENOSYS = 38;
constexpr int64_t LINUX_ENOMEM = 12;
constexpr int64_t LINUX_EINVAL = 22;
constexpr int64_t LINUX_EBADF  = 9;
constexpr int64_t LINUX_EACCES = 13;
constexpr int64_t LINUX_ENOENT = 2;

// Linux arch_prctl codes
constexpr uint64_t LINUX_ARCH_SET_GS = 0x1001;
constexpr uint64_t LINUX_ARCH_SET_FS = 0x1002;
constexpr uint64_t LINUX_ARCH_GET_FS = 0x1003;
constexpr uint64_t LINUX_ARCH_GET_GS = 0x1004;

// Linux protection flags
constexpr uint64_t LINUX_PROT_NONE  = 0x0;
constexpr uint64_t LINUX_PROT_READ  = 0x1;
constexpr uint64_t LINUX_PROT_WRITE = 0x2;
constexpr uint64_t LINUX_PROT_EXEC  = 0x4;

// Linux mmap flags
constexpr uint64_t LINUX_MAP_SHARED    = 0x01;
constexpr uint64_t LINUX_MAP_PRIVATE   = 0x02;
constexpr uint64_t LINUX_MAP_FIXED     = 0x10;
constexpr uint64_t LINUX_MAP_ANONYMOUS = 0x20;

// Forward declarations
class MemoryManager;
struct ElixirContext;

// Linux x86_64 syscall handler
// Installs a UC_HOOK_INSN for UC_X86_INS_SYSCALL and dispatches
// to appropriate handlers based on RAX (syscall number).
class LinuxSyscallHandler {
public:
    LinuxSyscallHandler(uc_engine* uc, MemoryManager* mem, ElixirContext* ctx);
    ~LinuxSyscallHandler();
    
    // No copy
    LinuxSyscallHandler(const LinuxSyscallHandler&) = delete;
    LinuxSyscallHandler& operator=(const LinuxSyscallHandler&) = delete;
    
    // Install the SYSCALL instruction hook
    void install_hook();
    
    // The hook callback (called by Unicorn)
    static void syscall_hook_cb(uc_engine* uc, void* user_data);
    
    // Dispatch based on RAX (syscall number)
    void dispatch(uc_engine* uc);
    
    // Get current brk address
    uint64_t current_brk() const { return current_brk_; }

private:
    uc_engine* uc_;
    MemoryManager* mem_;
    ElixirContext* ctx_;
    uc_hook hook_handle_ = 0;
    
    // brk state - initial program break
    uint64_t current_brk_ = 0x50000000;
    
    // mmap bump allocator
    uint64_t next_mmap_addr_ = 0x40000000;
    
    // Helper to read register
    static uint64_t read_reg(uc_engine* uc, int reg);
    
    // Syscall handlers (return value goes to RAX)
    // Negative values are -errno
    int64_t sys_read(uint64_t fd, uint64_t buf, uint64_t count);
    int64_t sys_write(uint64_t fd, uint64_t buf, uint64_t count);
    int64_t sys_open(uint64_t pathname, uint64_t flags, uint64_t mode);
    int64_t sys_close(uint64_t fd);
    int64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, 
                     uint64_t flags, uint64_t fd, uint64_t offset);
    int64_t sys_mprotect(uint64_t addr, uint64_t len, uint64_t prot);
    int64_t sys_munmap(uint64_t addr, uint64_t len);
    int64_t sys_brk(uint64_t addr);
    int64_t sys_ioctl(uint64_t fd, uint64_t cmd, uint64_t arg);
    int64_t sys_writev(uint64_t fd, uint64_t iov, uint64_t iovcnt);
    int64_t sys_access(uint64_t pathname, uint64_t mode);
    int64_t sys_exit(uint64_t code);
    int64_t sys_arch_prctl(uint64_t code, uint64_t addr);
    int64_t sys_exit_group(uint64_t code);
};

// Linux process environment setup
// Called after ELF load to set up stack, registers, and initial state
void setup_linux_process_env(uc_engine* uc, MemoryManager* mem);
