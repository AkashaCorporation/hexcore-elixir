// HexCore Elixir — Virtual File System
//
// Clean-room implementation. No code copied verbatim.
// Apache-2.0 licensed.

#if defined(_WIN32)
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
#endif

#include "elixir/vfs.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdio>

// ============================================================================
// Constructor
// ============================================================================

VirtualFileSystem::VirtualFileSystem(uc_engine* uc) : uc_(uc) {
    root_.is_dir = true;
}

// ============================================================================
// Path normalization
// ============================================================================

std::string VirtualFileSystem::normalize_path(const std::string& path) const {
    std::string result;
    result.reserve(path.size());

    // Convert backslashes to forward slashes, lowercase
    for (char c : path) {
        if (c == '\\') {
            result += '/';
        } else {
            result += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
    }

    // Strip drive letter prefix (e.g., "c:/")
    if (result.size() >= 3 && std::isalpha(static_cast<unsigned char>(result[0])) &&
        result[1] == ':' && result[2] == '/') {
        result = result.substr(3);
    }

    // Strip leading slash
    while (!result.empty() && result[0] == '/') {
        result = result.substr(1);
    }

    // Strip trailing slash
    while (!result.empty() && result.back() == '/') {
        result.pop_back();
    }

    return result;
}

std::string VirtualFileSystem::dirname(const std::string& path) const {
    auto pos = path.find_last_of('/');
    if (pos == std::string::npos) return "";
    return path.substr(0, pos);
}

std::string VirtualFileSystem::basename(const std::string& path) const {
    auto pos = path.find_last_of('/');
    if (pos == std::string::npos) return path;
    return path.substr(pos + 1);
}

// ============================================================================
// Tree traversal
// =================================================================++

VirtualFileSystem::VfsNode* VirtualFileSystem::find_node(const std::string& path) {
    std::string norm = normalize_path(path);
    if (norm.empty()) return &root_;

    VfsNode* current = &root_;
    size_t start = 0;

    while (start < norm.size()) {
        size_t end = norm.find('/', start);
        std::string component = norm.substr(start, end - start);
        start = (end == std::string::npos) ? norm.size() : end + 1;

        if (!current->is_dir) return nullptr;

        auto it = current->children.find(component);
        if (it == current->children.end()) return nullptr;

        current = it->second.get();
    }

    return current;
}

VirtualFileSystem::VfsNode* VirtualFileSystem::find_or_create_node(
    const std::string& path, bool create_dirs) {

    std::string norm = normalize_path(path);
    if (norm.empty()) return &root_;

    VfsNode* current = &root_;
    size_t start = 0;

    while (start < norm.size()) {
        size_t end = norm.find('/', start);
        std::string component = norm.substr(start, end - start);
        bool is_last = (end == std::string::npos);
        start = is_last ? norm.size() : end + 1;

        if (!current->is_dir) return nullptr;

        auto it = current->children.find(component);
        if (it == current->children.end()) {
            if (!create_dirs && !is_last) return nullptr;
            auto node = std::make_unique<VfsNode>();
            node->is_dir = !is_last;
            auto* ptr = node.get();
            current->children[component] = std::move(node);
            current = ptr;
        } else {
            current = it->second.get();
        }
    }

    return current;
}

// ============================================================================
// Guest memory helpers
// ============================================================================

std::string VirtualFileSystem::read_guest_string(uint64_t addr, size_t max_len) const {
    std::string result;
    result.reserve(256);
    for (size_t i = 0; i < max_len; i++) {
        uint8_t ch = 0;
        if (uc_mem_read(uc_, addr + i, &ch, 1) != UC_ERR_OK || ch == 0) break;
        result += static_cast<char>(ch);
    }
    return result;
}

// ============================================================================
// Console initialization
// ============================================================================

void VirtualFileSystem::init_console() {
    // Pre-register stdin/stdout/stderr as pseudo-handles
    // These don't go through the normal open path
    OpenFile stdin_file;
    stdin_file.path = "<stdin>";
    stdin_file.cursor = 0;
    stdin_file.writable = false;
    stdin_file.node = nullptr;
    open_handles_[VFS_HANDLE_STDIN] = stdin_file;

    OpenFile stdout_file;
    stdout_file.path = "<stdout>";
    stdout_file.cursor = 0;
    stdout_file.writable = true;
    stdout_file.node = nullptr;
    open_handles_[VFS_HANDLE_STDOUT] = stdout_file;

    OpenFile stderr_file;
    stderr_file.path = "<stderr>";
    stderr_file.cursor = 0;
    stderr_file.writable = true;
    stderr_file.node = nullptr;
    open_handles_[VFS_HANDLE_STDERR] = stderr_file;
}

// ============================================================================
// Core file operations
// ============================================================================

uint64_t VirtualFileSystem::open(const std::string& path, uint32_t flags, uint32_t mode) {
    (void)mode;

    std::string norm = normalize_path(path);
    if (norm.empty()) return 0;  // invalid path

    bool want_write = (flags & VFS_O_WRONLY) || (flags & VFS_O_RDWR);
    bool want_create = (flags & VFS_O_CREAT) != 0;
    bool want_truncate = (flags & VFS_O_TRUNC) != 0;
    bool want_append = (flags & VFS_O_APPEND) != 0;

    VfsNode* node = find_node(norm);

    if (!node && want_create) {
        // Create the file (and parent dirs if needed)
        node = find_or_create_node(norm, true);
        if (!node) return 0;
        node->is_dir = false;
    }

    if (!node) return 0;  // file not found

    // Can't open a directory for writing
    if (node->is_dir && want_write) return 0;

    // Truncate if requested
    if (want_truncate && want_write && !node->is_dir) {
        node->data.clear();
    }

    uint64_t handle = next_handle_++;

    OpenFile of;
    of.path = norm;
    of.cursor = want_append ? node->data.size() : 0;
    of.writable = want_write;
    of.append = want_append;
    of.node = node;

    open_handles_[handle] = of;
    return handle;
}

int64_t VirtualFileSystem::read(uint64_t handle, uint64_t guest_buf, uint64_t count) {
    auto it = open_handles_.find(handle);
    if (it == open_handles_.end()) return -1;

    OpenFile& of = it->second;
    if (!of.node || of.node->is_dir) return -1;

    auto& data = of.node->data;
    if (of.cursor >= data.size()) return 0;  // EOF

    uint64_t available = data.size() - of.cursor;
    uint64_t to_read = std::min(count, available);

    if (to_read == 0) return 0;

    uc_err err = uc_mem_write(uc_, guest_buf, data.data() + of.cursor, to_read);
    if (err != UC_ERR_OK) return -1;

    of.cursor += to_read;
    return static_cast<int64_t>(to_read);
}

int64_t VirtualFileSystem::write(uint64_t handle, uint64_t guest_buf, uint64_t count) {
    // Handle console pseudo-handles
    if (handle == VFS_HANDLE_STDOUT || handle == VFS_HANDLE_STDERR) {
        std::vector<uint8_t> buf(count);
        if (count > 0) {
            uc_err err = uc_mem_read(uc_, guest_buf, buf.data(), count);
            if (err != UC_ERR_OK) return -1;
        }
        std::string text(buf.begin(), buf.end());
        if (handle == VFS_HANDLE_STDOUT) {
            stdout_buffer_ += text;
        } else {
            stderr_buffer_ += text;
        }
        return static_cast<int64_t>(count);
    }

    auto it = open_handles_.find(handle);
    if (it == open_handles_.end()) return -1;

    OpenFile& of = it->second;
    if (!of.node || !of.writable) return -1;
    if (of.node->is_dir) return -1;

    // Read from guest memory
    std::vector<uint8_t> buf(count);
    if (count > 0) {
        uc_err err = uc_mem_read(uc_, guest_buf, buf.data(), count);
        if (err != UC_ERR_OK) return -1;
    }

    auto& data = of.node->data;

    if (of.append) {
        // Append mode: always write at end
        data.insert(data.end(), buf.begin(), buf.end());
        of.cursor = data.size();
    } else {
        // Normal write at cursor position
        uint64_t end_pos = of.cursor + count;
        if (end_pos > data.size()) {
            data.resize(end_pos);
        }
        std::memcpy(data.data() + of.cursor, buf.data(), count);
        of.cursor = end_pos;
    }

    return static_cast<int64_t>(count);
}

bool VirtualFileSystem::close(uint64_t handle) {
    // Don't allow closing console handles
    if (handle == VFS_HANDLE_STDIN ||
        handle == VFS_HANDLE_STDOUT ||
        handle == VFS_HANDLE_STDERR) {
        return true;  // succeed silently
    }

    auto it = open_handles_.find(handle);
    if (it == open_handles_.end()) return false;

    open_handles_.erase(it);
    return true;
}

int64_t VirtualFileSystem::seek(uint64_t handle, int64_t offset, int whence) {
    auto it = open_handles_.find(handle);
    if (it == open_handles_.end()) return -1;

    OpenFile& of = it->second;
    if (!of.node || of.node->is_dir) return -1;

    int64_t new_pos = 0;
    int64_t file_size = static_cast<int64_t>(of.node->data.size());

    switch (whence) {
        case VFS_SEEK_SET:
            new_pos = offset;
            break;
        case VFS_SEEK_CUR:
            new_pos = static_cast<int64_t>(of.cursor) + offset;
            break;
        case VFS_SEEK_END:
            new_pos = file_size + offset;
            break;
        default:
            return -1;
    }

    if (new_pos < 0) return -1;

    of.cursor = static_cast<uint64_t>(new_pos);
    return new_pos;
}

int64_t VirtualFileSystem::tell(uint64_t handle) {
    auto it = open_handles_.find(handle);
    if (it == open_handles_.end()) return -1;

    return static_cast<int64_t>(it->second.cursor);
}

int64_t VirtualFileSystem::get_size(uint64_t handle) {
    auto it = open_handles_.find(handle);
    if (it == open_handles_.end()) return -1;

    if (!it->second.node || it->second.node->is_dir) return -1;

    return static_cast<int64_t>(it->second.node->data.size());
}

bool VirtualFileSystem::is_valid_handle(uint64_t handle) const {
    return open_handles_.find(handle) != open_handles_.end();
}

// ============================================================================
// Tree management
// ============================================================================

void VirtualFileSystem::create_file(const std::string& path, const std::vector<uint8_t>& data) {
    VfsNode* node = find_or_create_node(path, true);
    if (node) {
        node->is_dir = false;
        node->data = data;
    }
}

void VirtualFileSystem::create_dir(const std::string& path) {
    VfsNode* node = find_or_create_node(path, true);
    if (node) {
        node->is_dir = true;
    }
}

// ============================================================================
// Stat
// ============================================================================

VirtualFileSystem::StatResult VirtualFileSystem::stat(const std::string& path) {
    StatResult result;
    VfsNode* node = find_node(path);
    if (!node) return result;

    result.exists = true;
    result.is_dir = node->is_dir;
    result.size = node->data.size();
    return result;
}

// ============================================================================
// Output capture
// ============================================================================

std::string VirtualFileSystem::get_stdout() const {
    return stdout_buffer_;
}

std::string VirtualFileSystem::get_stderr() const {
    return stderr_buffer_;
}

void VirtualFileSystem::clear_output() {
    stdout_buffer_.clear();
    stderr_buffer_.clear();
}
