// HexCore Elixir — Win32 Handler Extras (Registry, String conversion)
//
// Clean-room implementation. No code copied verbatim.
// Apache-2.0 licensed.

#pragma once

#include <unicorn/unicorn.h>
#include <cstdint>
#include <string>
#include <vector>

class MemoryManager;

// Registry handlers
uint64_t handle_RegOpenKeyExA(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args);
uint64_t handle_RegOpenKeyExW(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args);
uint64_t handle_RegQueryValueExA(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args);
uint64_t handle_RegQueryValueExW(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args);
uint64_t handle_RegCloseKey(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args);

// System information handlers
uint64_t handle_GetComputerNameA(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args);
uint64_t handle_GetComputerNameW(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args);

// String conversion handlers
uint64_t handle_WideCharToMultiByte(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args);
uint64_t handle_MultiByteToWideChar(uc_engine* uc, MemoryManager*, const std::vector<uint64_t>& args);
