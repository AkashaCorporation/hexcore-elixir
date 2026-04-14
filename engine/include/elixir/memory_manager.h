// HexCore Elixir — Memory Manager
//
// Clean-room implementation using:
//   - Unicorn Engine 2.0.1 C API (memory mapping, hooks)
//   - HexCore Elixir public API
//
// Apache-2.0 licensed. No code copied verbatim.

#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include <memory>
#include <unicorn/unicorn.h>
#include "elixir/elixir.h"

class MemoryManager {
public:
    struct Region {
        uint64_t base;
        uint64_t size;
        uint32_t prot;
        std::string name;
    };

private:
    uc_engine* uc_;
    bool permissive_memory_;
    uc_hook fault_hook_handle_ = 0;
    
    // Region tracking
    std::map<uint64_t, Region> regions_;
    
    // Heap allocator (first-fit free list)
    uint64_t heap_base_ = 0;
    uint64_t heap_size_ = 0;
    bool heap_initialized_ = false;
    
    struct FreeBlock {
        uint64_t offset;  // Offset from heap_base_
        uint64_t size;
    };
    std::vector<FreeBlock> free_list_;
    
    // Allocation tracking for heap_free
    std::map<uint64_t, uint64_t> allocations_;  // addr -> size
    
    // Static callback for Unicorn hook
    static bool fault_hook_callback(uc_engine* uc, uc_mem_type type,
                                     uint64_t address, int size, int64_t value,
                                     void* user_data);
    
    // Internal helpers
    static uint64_t align_up(uint64_t value, uint64_t alignment);
    static uint64_t align_down(uint64_t value, uint64_t alignment);
    bool has_overlap(uint64_t addr, uint64_t size) const;

public:
    static constexpr uint64_t PAGE_SIZE = 0x1000;
    static constexpr uint64_t DEFAULT_HEAP_BASE = 0x10000000;
    
    MemoryManager(uc_engine* uc, uint64_t heap_size, bool permissive);
    ~MemoryManager();
    
    // No copy
    MemoryManager(const MemoryManager&) = delete;
    MemoryManager& operator=(const MemoryManager&) = delete;
    
    // Core operations
    ElixirError map(uint64_t addr, uint64_t size, uint32_t prot, const std::string& name = "");
    ElixirError unmap(uint64_t addr, uint64_t size);
    ElixirError protect(uint64_t addr, uint64_t size, uint32_t prot);
    
    // Heap
    uint64_t heap_alloc(uint64_t size, bool zero = true);
    void heap_free(uint64_t addr);
    
    // Query
    bool is_mapped(uint64_t addr) const;
    const Region* find_region(uint64_t addr) const;
    const std::map<uint64_t, Region>& regions() const { return regions_; }
    
    // Config
    void set_permissive(bool enabled) { permissive_memory_ = enabled; }
    bool is_permissive() const { return permissive_memory_; }
};
