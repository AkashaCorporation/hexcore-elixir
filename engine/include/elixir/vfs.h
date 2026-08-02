// HexCore Elixir — Virtual File System
//
// Clean-room implementation. No code copied verbatim.
// Apache-2.0 licensed.

#pragma once

#include <unicorn/unicorn.h>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

// Open flags (POSIX-compatible)
#define VFS_O_RDONLY   0x0000
#define VFS_O_WRONLY   0x0001
#define VFS_O_RDWR     0x0002
#define VFS_O_CREAT    0x0100
#define VFS_O_TRUNC    0x0200
#define VFS_O_APPEND   0x0400

// Seek whence
#define VFS_SEEK_SET   0
#define VFS_SEEK_CUR   1
#define VFS_SEEK_END   2

// Special console pseudo-handles (matching GetStdHandle output)
#define VFS_HANDLE_STDIN   0x10
#define VFS_HANDLE_STDOUT  0x11
#define VFS_HANDLE_STDERR  0x12

// File handle base (Windows HANDLE range)
#define VFS_HANDLE_BASE    0xA0000000

class VirtualFileSystem {
public:
    VirtualFileSystem(uc_engine* uc);

    // Core file operations
    uint64_t open(const std::string& path, uint32_t flags, uint32_t mode = 0);
    int64_t  read(uint64_t handle, uint64_t guest_buf, uint64_t count);
    int64_t  write(uint64_t handle, uint64_t guest_buf, uint64_t count);
    bool     close(uint64_t handle);
    int64_t  seek(uint64_t handle, int64_t offset, int whence);
    int64_t  tell(uint64_t handle);
    int64_t  get_size(uint64_t handle);
    bool     is_valid_handle(uint64_t handle) const;

    // Tree management
    void create_file(const std::string& path, const std::vector<uint8_t>& data);
    void create_dir(const std::string& path);

    // stdout/stderr capture
    std::string get_stdout() const;
    std::string get_stderr() const;
    void clear_output();

    // Pre-registration of console handles
    void init_console();

    // Stat emulation
    struct StatResult {
        bool exists = false;
        bool is_dir = false;
        uint64_t size = 0;
    };
    StatResult stat(const std::string& path);

private:
    struct VfsNode {
        bool is_dir = false;
        std::vector<uint8_t> data;
        std::unordered_map<std::string, std::unique_ptr<VfsNode>> children;
    };

    struct OpenFile {
        std::string path;
        uint64_t cursor = 0;
        bool writable = false;
        bool append = false;
        VfsNode* node = nullptr;  // pointer into tree
    };

    uc_engine* uc_;
    VfsNode root_;
    std::unordered_map<uint64_t, OpenFile> open_handles_;
    uint64_t next_handle_ = VFS_HANDLE_BASE;
    std::string stdout_buffer_;
    std::string stderr_buffer_;

    // Helpers
    std::string normalize_path(const std::string& path) const;
    VfsNode* find_node(const std::string& path);
    VfsNode* find_or_create_node(const std::string& path, bool create_dirs = false);
    std::string read_guest_string(uint64_t addr, size_t max_len = 4096) const;
    std::string dirname(const std::string& path) const;
    std::string basename(const std::string& path) const;
};
