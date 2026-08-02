// HexCore Elixir — Linux Syscall Handlers
//
// Clean-room implementation of Linux syscall emulation for x86_64.
// Reference: Linux man pages, kernel UAPI headers (license exception for userspace use)
//
// SysV x64 Calling Convention for syscalls:
//   Syscall number: RAX
//   Arguments: RDI, RSI, RDX, R10, R8, R9  (NOTE: R10 instead of RCX!)
//   Return: RAX (negative values are -errno)
//
// Apache-2.0 licensed. No code copied verbatim.

#include "elixir/linux_syscalls.h"
#include "elixir/engine_internal.h"
#include "elixir/memory_manager.h"
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include <cstring>
#include <cstdio>
#include <cstdint>

// --- Helper functions ---

uint64_t LinuxSyscallHandler::read_reg(uc_engine* uc, int reg) {
    uint64_t val = 0;
    uc_reg_read(uc, reg, &val);
    return val;
}

// Read a null-terminated string from emulated memory
static std::string read_guest_string(uc_engine* uc, uint64_t addr, size_t max_len = 4096) {
    std::string result;
    for (size_t i = 0; i < max_len; i++) {
        uint8_t ch = 0;
        if (uc_mem_read(uc, addr + i, &ch, 1) != UC_ERR_OK || ch == 0) break;
        result += static_cast<char>(ch);
    }
    return result;
}

// --- Constructor / Destructor ---

LinuxSyscallHandler::LinuxSyscallHandler(uc_engine* uc, MemoryManager* mem, ElixirContext* ctx)
    : uc_(uc), mem_(mem), ctx_(ctx), current_brk_(0x50000000), next_mmap_addr_(0x40000000) {
}

LinuxSyscallHandler::~LinuxSyscallHandler() {
    if (hook_handle_ && uc_) {
        uc_hook_del(uc_, hook_handle_);
    }
}

// --- Hook installation ---

void LinuxSyscallHandler::syscall_hook_cb(uc_engine* uc, void* user_data) {
    auto* handler = static_cast<LinuxSyscallHandler*>(user_data);
    handler->dispatch(uc);
}

void LinuxSyscallHandler::install_hook() {
    uc_err err = uc_hook_add(uc_, &hook_handle_, UC_HOOK_INSN,
                              (void*)syscall_hook_cb, this, 1, 0, UC_X86_INS_SYSCALL);
    if (err != UC_ERR_OK) {
        // Failed to install syscall hook - this is critical
    }
}

// --- Dispatch ---

void LinuxSyscallHandler::dispatch(uc_engine* uc) {
    // Read syscall number and arguments
    uint64_t nr  = read_reg(uc, UC_X86_REG_RAX);
    uint64_t rdi = read_reg(uc, UC_X86_REG_RDI);
    uint64_t rsi = read_reg(uc, UC_X86_REG_RSI);
    uint64_t rdx = read_reg(uc, UC_X86_REG_RDX);
    uint64_t r10 = read_reg(uc, UC_X86_REG_R10);
    uint64_t r8  = read_reg(uc, UC_X86_REG_R8);
    uint64_t r9  = read_reg(uc, UC_X86_REG_R9);
    
    int64_t result = -LINUX_ENOSYS;  // Default: syscall not implemented
    
    // Dispatch based on syscall number
    switch (nr) {
        case 0:   // sys_read
            result = sys_read(rdi, rsi, rdx);
            break;
        case 1:   // sys_write
            result = sys_write(rdi, rsi, rdx);
            break;
        case 2:   // sys_open
            result = sys_open(rdi, rsi, rdx);
            break;
        case 3:   // sys_close
            result = sys_close(rdi);
            break;
        case 8:   // sys_lseek
            result = sys_lseek(rdi, rsi, rdx);
            break;
        case 9:   // sys_mmap
            result = sys_mmap(rdi, rsi, rdx, r10, r8, r9);
            break;
        case 10:  // sys_mprotect
            result = sys_mprotect(rdi, rsi, rdx);
            break;
        case 11:  // sys_munmap
            result = sys_munmap(rdi, rsi);
            break;
        case 12:  // sys_brk
            result = sys_brk(rdi);
            break;
        case 16:  // sys_ioctl
            result = sys_ioctl(rdi, rsi, rdx);
            break;
        case 20:  // sys_writev
            result = sys_writev(rdi, rsi, rdx);
            break;
        case 21:  // sys_access
            result = sys_access(rdi, rsi);
            break;
        case 60:  // sys_exit
            result = sys_exit(rdi);
            break;
        case 158: // sys_arch_prctl
            result = sys_arch_prctl(rdi, rsi);
            break;
        case 231: // sys_exit_group
            result = sys_exit_group(rdi);
            break;
        default:
            result = -LINUX_ENOSYS;
            break;
    }
    
    // Write return value to RAX
    uc_reg_write(uc, UC_X86_REG_RAX, &result);
}

// --- Syscall implementations ---

int64_t LinuxSyscallHandler::sys_read(uint64_t fd, uint64_t buf, uint64_t count) {
    if (!ctx_ || !ctx_->vfs) return -LINUX_EBADF;

    // stdin
    if (fd == 0) return 0;  // EOF for stdin

    // Map Linux fd to VFS handle: Linux fds 3+ map to VFS_HANDLE_BASE + (fd - 3)
    uint64_t handle = (fd <= 2) ? fd : (VFS_HANDLE_BASE + (fd - 3));

    return ctx_->vfs->read(handle, buf, count);
}

int64_t LinuxSyscallHandler::sys_write(uint64_t fd, uint64_t buf, uint64_t count) {
    if (!ctx_ || !ctx_->vfs) return -LINUX_EBADF;

    // stdout/stderr — map to VFS console handles
    if (fd == 1 || fd == 2) {
        uint64_t handle = (fd == 1) ? VFS_HANDLE_STDOUT : VFS_HANDLE_STDERR;
        return ctx_->vfs->write(handle, buf, count);
    }

    // Regular file fd
    uint64_t handle = VFS_HANDLE_BASE + (fd - 3);
    return ctx_->vfs->write(handle, buf, count);
}

int64_t LinuxSyscallHandler::sys_open(uint64_t pathname, uint64_t flags, uint64_t mode) {
    if (!ctx_ || !ctx_->vfs) return -LINUX_ENOENT;

    std::string path = read_guest_string(uc_, pathname);
    if (path.empty()) return -LINUX_ENOENT;

    // Translate Linux flags to VFS flags
    uint32_t vfs_flags = 0;
    uint32_t access = flags & 0x3;  // O_RDONLY=0, O_WRONLY=1, O_RDWR=2
    vfs_flags |= access;
    if (flags & 0x40)   vfs_flags |= VFS_O_CREAT;    // O_CREAT = 0x40
    if (flags & 0x200)  vfs_flags |= VFS_O_TRUNC;    // O_TRUNC = 0x200
    if (flags & 0x400)  vfs_flags |= VFS_O_APPEND;   // O_APPEND = 0x400

    uint64_t handle = ctx_->vfs->open(path, vfs_flags, static_cast<uint32_t>(mode));
    if (handle == 0) return -LINUX_ENOENT;

    // Convert VFS handle back to Linux fd (3+)
    return static_cast<int64_t>(handle - VFS_HANDLE_BASE + 3);
}

int64_t LinuxSyscallHandler::sys_close(uint64_t fd) {
    if (!ctx_ || !ctx_->vfs) return 0;

    if (fd <= 2) return 0;  // Don't close stdin/stdout/stderr

    uint64_t handle = VFS_HANDLE_BASE + (fd - 3);
    ctx_->vfs->close(handle);
    return 0;
}

int64_t LinuxSyscallHandler::sys_lseek(uint64_t fd, uint64_t offset, uint64_t whence) {
    if (!ctx_ || !ctx_->vfs) return -LINUX_EBADF;

    if (fd <= 2) return -LINUX_EBADF;  // Can't seek on console

    uint64_t handle = VFS_HANDLE_BASE + (fd - 3);

    int vfs_whence = VFS_SEEK_SET;
    if (whence == 1) vfs_whence = VFS_SEEK_CUR;
    if (whence == 2) vfs_whence = VFS_SEEK_END;

    return ctx_->vfs->seek(handle, static_cast<int64_t>(offset), vfs_whence);
}

int64_t LinuxSyscallHandler::sys_mmap(uint64_t addr, uint64_t len, uint64_t prot,
                                       uint64_t flags, uint64_t fd, uint64_t offset) {
    (void)fd;
    (void)offset;
    
    if (len == 0) {
        return -LINUX_EINVAL;
    }
    
    uint64_t aligned_len = (len + 0xFFF) & ~0xFFFULL;
    
    uint32_t uc_prot = UC_PROT_NONE;
    if (prot & LINUX_PROT_READ)  uc_prot |= UC_PROT_READ;
    if (prot & LINUX_PROT_WRITE) uc_prot |= UC_PROT_WRITE;
    if (prot & LINUX_PROT_EXEC)  uc_prot |= UC_PROT_EXEC;
    
    if (uc_prot == UC_PROT_NONE) {
        uc_prot = UC_PROT_READ | UC_PROT_WRITE;
    }
    
    if (addr == 0 || (flags & LINUX_MAP_ANONYMOUS)) {
        uint64_t result = next_mmap_addr_;
        uc_err err = uc_mem_map(uc_, result, aligned_len, uc_prot);
        
        if (err == UC_ERR_OK) {
            next_mmap_addr_ += aligned_len;
            mem_->map(result, aligned_len, uc_prot, "mmap");
            return static_cast<int64_t>(result);
        }
        
        ElixirError map_err = mem_->map(result, aligned_len, uc_prot, "mmap");
        if (map_err == ELIXIR_OK) {
            next_mmap_addr_ += aligned_len;
            return static_cast<int64_t>(result);
        }
        
        return -LINUX_ENOMEM;
    } else {
        uint64_t aligned_addr = addr & ~0xFFFULL;
        
        if (flags & LINUX_MAP_FIXED) {
            uc_mem_unmap(uc_, aligned_addr, aligned_len);
        }
        
        uc_err err = uc_mem_map(uc_, aligned_addr, aligned_len, uc_prot);
        if (err == UC_ERR_OK) {
            mem_->map(aligned_addr, aligned_len, uc_prot, "mmap_fixed");
            return static_cast<int64_t>(aligned_addr);
        }
        
        ElixirError map_err = mem_->map(aligned_addr, aligned_len, uc_prot, "mmap_fixed");
        if (map_err == ELIXIR_OK) {
            return static_cast<int64_t>(aligned_addr);
        }
        
        return -LINUX_ENOMEM;
    }
}

int64_t LinuxSyscallHandler::sys_mprotect(uint64_t addr, uint64_t len, uint64_t prot) {
    if (len == 0) {
        return -LINUX_EINVAL;
    }
    
    uint32_t uc_prot = UC_PROT_NONE;
    if (prot & LINUX_PROT_READ)  uc_prot |= UC_PROT_READ;
    if (prot & LINUX_PROT_WRITE) uc_prot |= UC_PROT_WRITE;
    if (prot & LINUX_PROT_EXEC)  uc_prot |= UC_PROT_EXEC;
    
    uint64_t aligned_addr = addr & ~0xFFFULL;
    uint64_t aligned_len = (len + 0xFFF) & ~0xFFFULL;
    
    uc_err err = uc_mem_protect(uc_, aligned_addr, aligned_len, uc_prot);
    if (err == UC_ERR_OK) {
        return 0;
    }
    
    ElixirError prot_err = mem_->protect(aligned_addr, aligned_len, uc_prot);
    if (prot_err == ELIXIR_OK) {
        return 0;
    }
    
    return -LINUX_EINVAL;
}

int64_t LinuxSyscallHandler::sys_munmap(uint64_t addr, uint64_t len) {
    if (len == 0) {
        return -LINUX_EINVAL;
    }
    
    uint64_t aligned_addr = addr & ~0xFFFULL;
    uint64_t aligned_len = (len + 0xFFF) & ~0xFFFULL;
    
    uc_err err = uc_mem_unmap(uc_, aligned_addr, aligned_len);
    if (err == UC_ERR_OK) {
        mem_->unmap(aligned_addr, aligned_len);
        return 0;
    }
    
    ElixirError unmap_err = mem_->unmap(aligned_addr, aligned_len);
    if (unmap_err == ELIXIR_OK) {
        return 0;
    }
    
    return -LINUX_EINVAL;
}

int64_t LinuxSyscallHandler::sys_brk(uint64_t addr) {
    if (addr == 0) {
        return static_cast<int64_t>(current_brk_);
    }
    
    if (addr < current_brk_) {
        return static_cast<int64_t>(current_brk_);
    }
    
    uint64_t size = ((addr - current_brk_) + 0xFFF) & ~0xFFFULL;
    
    uc_err err = uc_mem_map(uc_, current_brk_, size, UC_PROT_READ | UC_PROT_WRITE);
    if (err == UC_ERR_OK) {
        mem_->map(current_brk_, size, UC_PROT_READ | UC_PROT_WRITE, "brk");
        current_brk_ += size;
        return static_cast<int64_t>(addr);
    }
    
    ElixirError map_err = mem_->map(current_brk_, size, UC_PROT_READ | UC_PROT_WRITE, "brk");
    if (map_err == ELIXIR_OK) {
        current_brk_ += size;
        return static_cast<int64_t>(addr);
    }
    
    return static_cast<int64_t>(current_brk_);
}

int64_t LinuxSyscallHandler::sys_ioctl(uint64_t fd, uint64_t cmd, uint64_t arg) {
    (void)fd;
    (void)cmd;
    (void)arg;
    return 0;
}

int64_t LinuxSyscallHandler::sys_writev(uint64_t fd, uint64_t iov, uint64_t iovcnt) {
    if (!ctx_ || !ctx_->vfs) return -LINUX_EBADF;

    // stdout/stderr — write scatter-gather buffers through VFS
    if (fd == 1 || fd == 2) {
        uint64_t handle = (fd == 1) ? VFS_HANDLE_STDOUT : VFS_HANDLE_STDERR;
        int64_t total = 0;

        // Each iov entry is {void* iov_base, size_t iov_len} = 16 bytes on x86_64
        for (uint64_t i = 0; i < iovcnt; i++) {
            uint64_t iov_base = 0;
            uint64_t iov_len = 0;
            uc_mem_read(uc_, iov + i * 16, &iov_base, 8);
            uc_mem_read(uc_, iov + i * 16 + 8, &iov_len, 8);

            if (iov_len > 0) {
                int64_t written = ctx_->vfs->write(handle, iov_base, iov_len);
                if (written > 0) total += written;
            }
        }
        return total;
    }

    return -LINUX_EBADF;
}

int64_t LinuxSyscallHandler::sys_access(uint64_t pathname, uint64_t mode) {
    (void)mode;
    if (!ctx_ || !ctx_->vfs) return -LINUX_ENOENT;

    std::string path = read_guest_string(uc_, pathname);
    if (path.empty()) return -LINUX_ENOENT;

    auto st = ctx_->vfs->stat(path);
    return st.exists ? 0 : -LINUX_ENOENT;
}

int64_t LinuxSyscallHandler::sys_exit(uint64_t code) {
    (void)code;
    
    if (ctx_) {
        ctx_->stop_reason = ELIXIR_STOP_EXIT;
    }
    
    uc_emu_stop(uc_);
    return 0;
}

int64_t LinuxSyscallHandler::sys_arch_prctl(uint64_t code, uint64_t addr) {
    switch (code) {
        case LINUX_ARCH_SET_FS:
            uc_reg_write(uc_, UC_X86_REG_FS_BASE, &addr);
            return 0;
            
        case LINUX_ARCH_SET_GS:
            uc_reg_write(uc_, UC_X86_REG_GS_BASE, &addr);
            return 0;
            
        case LINUX_ARCH_GET_FS: {
            uint64_t fs_base = 0;
            uc_reg_read(uc_, UC_X86_REG_FS_BASE, &fs_base);
            if (addr != 0) {
                uc_mem_write(uc_, addr, &fs_base, 8);
            }
            return 0;
        }
            
        case LINUX_ARCH_GET_GS: {
            uint64_t gs_base = 0;
            uc_reg_read(uc_, UC_X86_REG_GS_BASE, &gs_base);
            if (addr != 0) {
                uc_mem_write(uc_, addr, &gs_base, 8);
            }
            return 0;
        }
            
        default:
            return -LINUX_EINVAL;
    }
}

int64_t LinuxSyscallHandler::sys_exit_group(uint64_t code) {
    return sys_exit(code);
}
