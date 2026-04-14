// HexCore Elixir — Stalker Implementation
//
// Clean-room implementation. No code copied verbatim.
// Apache-2.0 licensed.

#include "elixir/stalker.h"
#include <cstring>
#include <sstream>

Stalker::Stalker(uc_engine* uc) : uc_(uc) {}

Stalker::~Stalker() {
    unfollow();
}

void Stalker::block_hook_callback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* self = static_cast<Stalker*>(user_data);
    
    BlockEvent event;
    event.pc = address;
    event.size = size;
    event.flags = 0;
    
    self->events_.push_back(event);
    self->block_count_++;
}

void Stalker::follow() {
    if (following_) return;
    
    // Install UC_HOOK_BLOCK on full address range
    uc_err err = uc_hook_add(uc_, &block_hook_handle_, UC_HOOK_BLOCK,
                             (void*)block_hook_callback, this,
                             1, 0);  // 1 to 0 = full range
    
    if (err == UC_ERR_OK) {
        following_ = true;
    }
}

void Stalker::unfollow() {
    if (!following_) return;
    
    if (block_hook_handle_) {
        uc_hook_del(uc_, block_hook_handle_);
        block_hook_handle_ = 0;
    }
    following_ = false;
}

void Stalker::clear_events() {
    events_.clear();
    block_count_ = 0;
}

std::vector<uint8_t> Stalker::export_drcov(uint64_t module_base, uint64_t module_size, const std::string& module_name) const {
    std::vector<uint8_t> result;
    
    // Build text header
    std::ostringstream header;
    header << "DRCOV VERSION: 2\n";
    header << "DRCOV FLAVOR: elixir\n";
    header << "Module Table: version 2, count 1\n";
    header << "Columns: id, containing_id, start, end, entry, offset, path\n";
    
    // Module entry: format hex addresses without 0x prefix for DRCOV compatibility
    char line[512];
    snprintf(line, sizeof(line), " 0, 0, 0x%llx, 0x%llx, 0x%llx, 0x0, %s\n",
             (unsigned long long)module_base,
             (unsigned long long)(module_base + module_size),
             (unsigned long long)module_base,
             module_name.c_str());
    header << line;
    
    // Count basic blocks within module range
    uint32_t bb_count = 0;
    for (const auto& evt : events_) {
        if (evt.pc >= module_base && evt.pc < module_base + module_size) {
            bb_count++;
        }
    }
    
    header << "BB Table: " << bb_count << " bbs\n";
    
    std::string hdr_str = header.str();
    
    // Write header bytes
    result.insert(result.end(), hdr_str.begin(), hdr_str.end());
    
    // Write binary BB entries: [uint32_t offset, uint16_t size, uint16_t module_id]
    for (const auto& evt : events_) {
        if (evt.pc >= module_base && evt.pc < module_base + module_size) {
            uint32_t offset = (uint32_t)(evt.pc - module_base);
            uint16_t size = (uint16_t)evt.size;
            uint16_t mod_id = 0;
            
            // Append as little-endian binary
            result.insert(result.end(), (uint8_t*)&offset, (uint8_t*)&offset + 4);
            result.insert(result.end(), (uint8_t*)&size, (uint8_t*)&size + 2);
            result.insert(result.end(), (uint8_t*)&mod_id, (uint8_t*)&mod_id + 2);
        }
    }
    
    return result;
}
