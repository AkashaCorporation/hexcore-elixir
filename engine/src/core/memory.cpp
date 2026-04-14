// HexCore Elixir — Memory Manager
//
// Clean-room implementation using:
//   - Unicorn Engine 2.0.1 C API (memory mapping, hooks)
//   - HexCore Elixir public API
//
// Apache-2.0 licensed. No code copied verbatim.

#include "elixir/memory_manager.h"
#include <algorithm>
#include <cstring>
#include <cstdio>

// ============================================================================
// Static helpers
// ============================================================================

uint64_t MemoryManager::align_up(uint64_t value, uint64_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

uint64_t MemoryManager::align_down(uint64_t value, uint64_t alignment) {
    return value & ~(alignment - 1);
}

// ============================================================================
// Fault hook callback (static)
// ============================================================================

bool MemoryManager::fault_hook_callback(uc_engine* uc, uc_mem_type type,
                                         uint64_t address, int size, int64_t value,
                                         void* user_data) {
    (void)type;
    (void)size;
    (void)value;
    
    auto* self = static_cast<MemoryManager*>(user_data);
    
    // If not permissive, let Unicorn raise the error
    if (!self->permissive_memory_) {
        return false;
    }
    
    // NULL page protection - only protect page 0 (address 0)
    // Allow mapping of addresses 0x1 - 0xFFF to handle CRT edge cases
    if (address == 0) {
        return false;
    }
    
    // Align address down to page boundary
    uint64_t page_addr = align_down(address, PAGE_SIZE);
    
    // Map a single page with all permissions
    uc_err err = uc_mem_map(uc, page_addr, PAGE_SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        return false;
    }
    
    // Add to regions tracking
    Region region;
    region.base = page_addr;
    region.size = PAGE_SIZE;
    region.prot = UC_PROT_ALL;
    region.name = "auto-mapped";
    self->regions_[page_addr] = region;
    
    return true;  // Continue execution
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

MemoryManager::MemoryManager(uc_engine* uc, uint64_t heap_size, bool permissive)
    : uc_(uc), permissive_memory_(permissive) {
    
    // Register fault hook for unmapped memory access
    // begin=1 to skip NULL page (0x0)
    uc_err err = uc_hook_add(uc_, &fault_hook_handle_,
        UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
        (void*)fault_hook_callback, this, 1, 0);
    
    // Hook registration failure is not fatal - just continue without fault handling
    (void)err;
    
    // Initialize heap if requested
    if (heap_size > 0) {
        heap_base_ = DEFAULT_HEAP_BASE;
        heap_size_ = heap_size;
        heap_initialized_ = true;
        
        // Map heap memory
        uc_err map_err = uc_mem_map(uc_, heap_base_, heap_size_, UC_PROT_READ | UC_PROT_WRITE);
        if (map_err == UC_ERR_OK) {
            // Add to regions tracking
            Region region;
            region.base = heap_base_;
            region.size = heap_size_;
            region.prot = UC_PROT_READ | UC_PROT_WRITE;
            region.name = "heap";
            regions_[heap_base_] = region;
            
            // Initialize free list with one big block
            free_list_.push_back({0, heap_size_});
        } else {
            // Heap initialization failed - mark as not initialized
            heap_initialized_ = false;
            heap_size_ = 0;
        }
    }
}

MemoryManager::~MemoryManager() {
    // Remove fault hook if it was registered
    if (fault_hook_handle_ != 0 && uc_) {
        uc_hook_del(uc_, fault_hook_handle_);
    }
}

// ============================================================================
// Core memory operations
// ============================================================================

ElixirError MemoryManager::map(uint64_t addr, uint64_t size, uint32_t prot, const std::string& name) {
    if (!uc_) {
        return ELIXIR_ERR_ARGS;
    }
    
    // Align address down and size up to page boundaries
    uint64_t aligned_addr = align_down(addr, PAGE_SIZE);
    uint64_t end_addr = addr + size;
    uint64_t aligned_end = align_up(end_addr, PAGE_SIZE);
    uint64_t aligned_size = aligned_end - aligned_addr;
    
    // Check for overlap with existing regions
    if (has_overlap(aligned_addr, aligned_size)) {
        return ELIXIR_ERR_MEMORY;
    }
    
    // Call uc_mem_map
    uc_err err = uc_mem_map(uc_, aligned_addr, aligned_size, prot);
    if (err != UC_ERR_OK) {
        return ELIXIR_ERR_UNICORN;
    }
    
    // Add to regions tracking
    Region region;
    region.base = aligned_addr;
    region.size = aligned_size;
    region.prot = prot;
    region.name = name;
    regions_[aligned_addr] = region;
    
    return ELIXIR_OK;
}

ElixirError MemoryManager::unmap(uint64_t addr, uint64_t size) {
    if (!uc_) {
        return ELIXIR_ERR_ARGS;
    }

    // Align address down and size up to page boundaries (same as map())
    uint64_t aligned_addr = align_down(addr, PAGE_SIZE);
    uint64_t end_addr = addr + size;
    uint64_t aligned_end = align_up(end_addr, PAGE_SIZE);
    uint64_t aligned_size = aligned_end - aligned_addr;

    // Find and remove region from tracking
    auto it = regions_.find(aligned_addr);
    if (it != regions_.end()) {
        regions_.erase(it);
    }

    // Call uc_mem_unmap with aligned values
    uc_err err = uc_mem_unmap(uc_, aligned_addr, aligned_size);
    if (err != UC_ERR_OK) {
        return ELIXIR_ERR_UNICORN;
    }

    return ELIXIR_OK;
}

ElixirError MemoryManager::protect(uint64_t addr, uint64_t size, uint32_t prot) {
    if (!uc_) {
        return ELIXIR_ERR_ARGS;
    }
    
    // Call uc_mem_protect
    uc_err err = uc_mem_protect(uc_, addr, size, prot);
    if (err != UC_ERR_OK) {
        return ELIXIR_ERR_UNICORN;
    }
    
    // Update region metadata
    // Find region containing this address
    for (auto& [base, region] : regions_) {
        if (base == addr) {
            region.prot = prot;
            break;
        }
    }
    
    return ELIXIR_OK;
}

// ============================================================================
// Heap allocator (first-fit)
// ============================================================================

uint64_t MemoryManager::heap_alloc(uint64_t size, bool zero) {
    if (!heap_initialized_ || size == 0) {
        return 0;
    }
    
    // Align size to page boundary
    uint64_t aligned_size = align_up(size, PAGE_SIZE);
    
    // First-fit search
    for (auto it = free_list_.begin(); it != free_list_.end(); ++it) {
        if (it->size >= aligned_size) {
            uint64_t offset = it->offset;
            
            if (it->size == aligned_size) {
                // Exact fit - remove block
                free_list_.erase(it);
            } else {
                // Split block
                it->offset += aligned_size;
                it->size -= aligned_size;
            }
            
            uint64_t addr = heap_base_ + offset;

            // Record allocation for heap_free
            allocations_[addr] = aligned_size;

            // Zero memory if requested
            if (zero) {
                std::vector<uint8_t> zeros(aligned_size, 0);
                uc_mem_write(uc_, addr, zeros.data(), aligned_size);
            }

            return addr;
        }
    }
    
    // No suitable block found
    return 0;
}

void MemoryManager::heap_free(uint64_t addr) {
    if (!heap_initialized_ || addr < heap_base_ || addr >= heap_base_ + heap_size_) {
        return;
    }

    // Look up the allocation size
    auto it = allocations_.find(addr);
    if (it == allocations_.end()) {
        return;  // Unknown allocation, ignore
    }

    // Convert address to offset
    uint64_t offset = addr - heap_base_;
    uint64_t block_size = it->second;
    allocations_.erase(it);

    // Add block back to free list
    free_list_.push_back({offset, block_size});

    // Coalesce adjacent blocks
    // Sort by offset
    std::sort(free_list_.begin(), free_list_.end(),
        [](const FreeBlock& a, const FreeBlock& b) {
            return a.offset < b.offset;
        });

    // Merge adjacent blocks
    std::vector<FreeBlock> merged;
    for (const auto& block : free_list_) {
        if (merged.empty()) {
            merged.push_back(block);
        } else {
            FreeBlock& last = merged.back();
            if (last.offset + last.size == block.offset) {
                // Adjacent - merge
                last.size += block.size;
            } else {
                merged.push_back(block);
            }
        }
    }

    free_list_ = std::move(merged);
}

// ============================================================================
// Query operations
// ============================================================================

bool MemoryManager::is_mapped(uint64_t addr) const {
    for (const auto& [base, region] : regions_) {
        if (addr >= region.base && addr < region.base + region.size) {
            return true;
        }
    }
    return false;
}

const MemoryManager::Region* MemoryManager::find_region(uint64_t addr) const {
    for (const auto& [base, region] : regions_) {
        if (addr >= region.base && addr < region.base + region.size) {
            return &region;
        }
    }
    return nullptr;
}

bool MemoryManager::has_overlap(uint64_t addr, uint64_t size) const {
    uint64_t end = addr + size;
    for (const auto& [base, region] : regions_) {
        uint64_t region_end = region.base + region.size;
        // Check if [addr, end) overlaps with [base, region_end)
        if (addr < region_end && end > region.base) {
            return true;
        }
    }
    return false;
}
