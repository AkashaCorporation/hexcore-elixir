// HexCore Elixir — Stalker (Basic Block Tracer)
//
// Clean-room implementation using Unicorn Engine 2.0.1 UC_HOOK_BLOCK.
// Inspired by Frida Stalker API pattern. No code copied verbatim.
//
// Apache-2.0 licensed.

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unicorn/unicorn.h>

struct BlockEvent {
    uint64_t pc;
    uint32_t size;
    uint32_t flags;  // reserved for future: is_call, is_ret, etc.
};

class Stalker {
    uc_engine* uc_;
    uc_hook block_hook_handle_ = 0;
    bool following_ = false;
    
    std::vector<BlockEvent> events_;
    uint64_t block_count_ = 0;
    
    static void block_hook_callback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    
public:
    Stalker(uc_engine* uc);
    ~Stalker();
    
    void follow();
    void unfollow();
    bool is_following() const { return following_; }
    
    uint64_t block_count() const { return block_count_; }
    const std::vector<BlockEvent>& events() const { return events_; }
    void clear_events();
    
    // DRCOV export — returns binary data in DRCOV v2 format
    std::vector<uint8_t> export_drcov(uint64_t module_base, uint64_t module_size, const std::string& module_name) const;
};
