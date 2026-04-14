// HexCore Elixir — Win32 Registry and String Stubs
//
// Clean-room implementation. No code copied verbatim.
// Apache-2.0 licensed.

#define NOMINMAX

#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

class MemoryManager;

// Helper to read a narrow string from emulated memory
static std::string read_string_from_mem(uc_engine* uc, uint64_t addr, size_t max_len = 256) {
    std::string result;
    for (size_t i = 0; i < max_len; i++) {
        uint8_t ch = 0;
        uc_mem_read(uc, addr + i, &ch, 1);
        if (ch == 0) break;
        result += (char)ch;
    }
    return result;
}

// Helper to read a wide string from emulated memory
static std::string read_wstring_from_mem(uc_engine* uc, uint64_t addr, size_t max_len = 256) {
    std::string result;
    for (size_t i = 0; i < max_len; i++) {
        uint16_t ch = 0;
        uc_mem_read(uc, addr + i * 2, &ch, 2);
        if (ch == 0) break;
        result += (char)(ch & 0xFF);  // Simple truncation
    }
    return result;
}

// Helper to write a narrow string to emulated memory
static void write_string_to_mem(uc_engine* uc, uint64_t addr, const std::string& str) {
    uc_mem_write(uc, addr, str.c_str(), str.size() + 1);
}

// Helper to write a wide string to emulated memory
static void write_wstring_to_mem(uc_engine* uc, uint64_t addr, const std::string& str) {
    for (size_t i = 0; i <= str.size(); i++) {
        uint16_t ch = (i < str.size()) ? (uint16_t)(uint8_t)str[i] : 0;
        uc_mem_write(uc, addr + i * 2, &ch, 2);
    }
}

// Static counter for fake HKEY handles
static uint64_t next_reg_handle = 0x90000000;

// Helper to read a narrow string from emulated memory (forward declaration)
static std::string read_string_from_mem(uc_engine* uc, uint64_t addr, size_t max_len);

// RegOpenKeyExA: args[0]=hKey, args[1]=lpSubKey, args[2]=ulOptions, args[3]=samDesired, args[4]=phkResult
uint64_t handle_RegOpenKeyExA(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args) {
    // Check if this is a VM-related registry path - return ERROR_FILE_NOT_FOUND
    // so the anti-VM check passes (no VM detected)
    if (args.size() > 1 && args[1] != 0) {
        std::string subkey = read_string_from_mem(uc, args[1]);
        // Convert to lowercase for comparison
        std::string lower_subkey;
        for (char c : subkey) {
            lower_subkey += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        
        // VM registry paths that should NOT be found
        const char* vm_paths[] = {
            "virtualbox", "vmware", "qemu", "sandbox", "xen", "parallels"
        };
        
        for (const char* vm_path : vm_paths) {
            if (lower_subkey.find(vm_path) != std::string::npos) {
                // Return ERROR_FILE_NOT_FOUND (2) - VM not detected
                return 2;
            }
        }
    }
    
    // For non-VM paths, return success with a fake handle
    uint64_t handle = next_reg_handle++;
    if (args.size() > 4 && args[4] != 0) {
        uc_mem_write(uc, args[4], &handle, 8);
    }
    return 0;  // ERROR_SUCCESS
}

// RegOpenKeyExW: same but wide
uint64_t handle_RegOpenKeyExW(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args) {
    return handle_RegOpenKeyExA(uc, nullptr, args);  // Same logic
}

// RegQueryValueExA: args[0]=hKey, args[1]=lpValueName, args[2]=lpReserved, args[3]=lpType, args[4]=lpData, args[5]=lpcbData
// Return ERROR_FILE_NOT_FOUND (2) for most queries
uint64_t handle_RegQueryValueExA(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args) {
    (void)uc;
    (void)args;
    return 2;  // ERROR_FILE_NOT_FOUND
}

uint64_t handle_RegQueryValueExW(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args) {
    (void)uc;
    (void)args;
    return 2;  // ERROR_FILE_NOT_FOUND
}

// RegCloseKey
uint64_t handle_RegCloseKey(uc_engine*, MemoryManager*, const std::vector<uint64_t>&) {
    return 0;  // ERROR_SUCCESS
}

// GetComputerNameA: args[0]=lpBuffer, args[1]=nSize
uint64_t handle_GetComputerNameA(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args) {
    // Use a shorter, simpler name that definitely won't match any VM strings
    const std::string name = "DESKTOP-ABC123";
    if (args.size() > 1 && args[0] != 0 && args[1] != 0) {
        write_string_to_mem(uc, args[0], name);
        // nSize should contain the size of the buffer on input
        // and the length of the string (not including null) on output
        uint32_t len = (uint32_t)name.size();
        uc_mem_write(uc, args[1], &len, 4);
    }
    return 1;  // TRUE
}

// GetComputerNameW: same but wide
uint64_t handle_GetComputerNameW(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args) {
    const std::string name = "DESKTOP-USER01";
    if (args.size() > 1 && args[0] != 0 && args[1] != 0) {
        write_wstring_to_mem(uc, args[0], name);
        uint32_t len = (uint32_t)name.size();
        uc_mem_write(uc, args[1], &len, 4);
    }
    return 1;  // TRUE
}

// WideCharToMultiByte: simplified - truncate upper byte
// args[0]=CodePage, args[1]=dwFlags, args[2]=lpWideCharStr, args[3]=cchWideChar,
// args[4]=lpMultiByteStr, args[5]=cbMultiByte, args[6]=lpDefaultChar, args[7]=lpUsedDefaultChar
uint64_t handle_WideCharToMultiByte(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args) {
    if (args.size() < 6) return 0;
    uint64_t src_addr = args[2];
    int32_t src_len = (int32_t)args[3];
    uint64_t dst_addr = args[4];
    int32_t dst_size = (int32_t)args[5];
    
    if (src_addr == 0) return 0;
    
    // Read wide string
    std::string narrow;
    if (src_len == -1) {
        narrow = read_wstring_from_mem(uc, src_addr);
        narrow += '\0';
    } else {
        for (int i = 0; i < src_len && i < 256; i++) {
            uint16_t ch = 0;
            uc_mem_read(uc, src_addr + i * 2, &ch, 2);
            narrow += (char)(ch & 0xFF);
        }
    }
    
    if (dst_addr == 0 || dst_size == 0) {
        return (uint64_t)narrow.size();
    }
    
    size_t to_write = std::min((size_t)dst_size, narrow.size());
    uc_mem_write(uc, dst_addr, narrow.data(), to_write);
    return (uint64_t)to_write;
}

// MultiByteToWideChar: simplified - zero-extend
// args[0]=CodePage, args[1]=dwFlags, args[2]=lpMultiByteStr, args[3]=cbMultiByte,
// args[4]=lpWideCharStr, args[5]=cchWideChar
uint64_t handle_MultiByteToWideChar(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args) {
    if (args.size() < 6) return 0;
    uint64_t src_addr = args[2];
    int32_t src_len = (int32_t)args[3];
    uint64_t dst_addr = args[4];
    int32_t dst_size = (int32_t)args[5];
    
    if (src_addr == 0) return 0;
    
    std::string narrow;
    if (src_len == -1) {
        narrow = read_string_from_mem(uc, src_addr);
        narrow += '\0';
    } else {
        char buf[256];
        size_t to_read = std::min((size_t)src_len, sizeof(buf));
        uc_mem_read(uc, src_addr, buf, to_read);
        narrow.assign(buf, to_read);
    }
    
    if (dst_addr == 0 || dst_size == 0) {
        return (uint64_t)narrow.size();
    }
    
    size_t to_write = std::min((size_t)dst_size, narrow.size());
    for (size_t i = 0; i < to_write; i++) {
        uint16_t ch = (uint8_t)narrow[i];
        uc_mem_write(uc, dst_addr + i * 2, &ch, 2);
    }
    return (uint64_t)to_write;
}
