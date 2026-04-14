// HexCore Elixir — Interceptor Implementation
//
// Clean-room implementation. No code copied verbatim.
// Apache-2.0 licensed.

#include "elixir/interceptor.h"
#include "elixir/memory_manager.h"
#include <unicorn/x86.h>

Interceptor::Interceptor(uc_engine* uc, MemoryManager* mem)
    : uc_(uc), mem_(mem) {}

Interceptor::~Interceptor() {
    detach_all();
}

uint64_t Interceptor::read_reg(int regid) {
    uint64_t val = 0;
    uc_reg_read(uc_, regid, &val);
    return val;
}

std::vector<uint64_t> Interceptor::read_args(int count) {
    std::vector<uint64_t> args;
    if (count > 0) args.push_back(read_reg(UC_X86_REG_RCX));
    if (count > 1) args.push_back(read_reg(UC_X86_REG_RDX));
    if (count > 2) args.push_back(read_reg(UC_X86_REG_R8));
    if (count > 3) args.push_back(read_reg(UC_X86_REG_R9));
    // Stack args if needed
    uint64_t rsp = read_reg(UC_X86_REG_RSP);
    for (int i = 4; i < count; i++) {
        uint64_t val = 0;
        uc_mem_read(uc_, rsp + 0x28 + (i - 4) * 8, &val, 8);
        args.push_back(val);
    }
    return args;
}

void Interceptor::enter_hook_callback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* self = static_cast<Interceptor*>(user_data);
    
    auto it = self->entries_.find(address);
    if (it == self->entries_.end()) return;
    
    auto& entry = it->second;
    
    // Read arguments
    auto args = self->read_args(4);
    
    // Call onEnter
    if (entry.on_enter) {
        entry.on_enter(uc, address, args);
    }
    
    // Read return address for onLeave setup
    uint64_t rsp = self->read_reg(UC_X86_REG_RSP);
    uint64_t ret_addr = 0;
    uc_mem_read(uc, rsp, &ret_addr, 8);
    
    // If onLeave is set, install a temporary hook at the return address
    if (entry.on_leave && ret_addr != 0) {
        uc_hook hook_handle = 0;
        
        // Create a lambda-based callback for the return hook
        // We need to capture the context, so we use the pending_returns_ vector
        PendingReturn pending;
        pending.target_addr = address;
        pending.return_addr = ret_addr;
        pending.return_hook_handle = 0;
        
        // Install hook at return address
        uc_err err = uc_hook_add(self->uc_, &hook_handle, UC_HOOK_CODE,
                                 (void*)[](uc_engine* uc2, uint64_t addr2, uint32_t sz2, void* ud2) {
                                     auto* interceptor = static_cast<Interceptor*>(ud2);
                                     
                                     // Find the pending return for this address
                                     for (auto pit = interceptor->pending_returns_.begin(); 
                                          pit != interceptor->pending_returns_.end(); ++pit) {
                                         if (pit->return_addr == addr2) {
                                             // Read retval from RAX
                                             uint64_t rax = interceptor->read_reg(UC_X86_REG_RAX);
                                             
                                             // Call onLeave
                                             auto eit = interceptor->entries_.find(pit->target_addr);
                                             if (eit != interceptor->entries_.end() && eit->second.on_leave) {
                                                 std::vector<uint64_t> leave_args = {rax};
                                                 eit->second.on_leave(uc2, pit->target_addr, leave_args);
                                             }
                                             
                                             // Log
                                             interceptor->log_.push_back({pit->target_addr, rax});
                                             
                                             // Remove the temporary hook
                                             uc_hook_del(uc2, pit->return_hook_handle);
                                             interceptor->pending_returns_.erase(pit);
                                             break;
                                         }
                                     }
                                 },
                                 self, ret_addr, ret_addr);
        
        if (err == UC_ERR_OK) {
            pending.return_hook_handle = hook_handle;
            self->pending_returns_.push_back(pending);
        }
    } else {
        // No onLeave, just log the enter
        self->log_.push_back({address, 0});
    }
}

void Interceptor::attach(uint64_t addr, InterceptorCallback on_enter, InterceptorCallback on_leave) {
    // Don't double-attach
    if (entries_.find(addr) != entries_.end()) return;
    
    InterceptorEntry entry;
    entry.target_addr = addr;
    entry.on_enter = on_enter;
    entry.on_leave = on_leave;
    
    // Install UC_HOOK_CODE at this specific address
    uc_hook hook = 0;
    uc_err err = uc_hook_add(uc_, &hook, UC_HOOK_CODE,
                             (void*)enter_hook_callback, this,
                             addr, addr);
    
    if (err == UC_ERR_OK) {
        entry.hook_handle = hook;
        entries_[addr] = entry;
    }
}

void Interceptor::detach(uint64_t addr) {
    auto it = entries_.find(addr);
    if (it == entries_.end()) return;
    
    if (it->second.hook_handle) {
        uc_hook_del(uc_, it->second.hook_handle);
    }
    entries_.erase(it);
}

void Interceptor::detach_all() {
    for (auto& [addr, entry] : entries_) {
        if (entry.hook_handle) {
            uc_hook_del(uc_, entry.hook_handle);
        }
    }
    entries_.clear();
    
    // Clean up pending return hooks
    for (auto& pending : pending_returns_) {
        if (pending.return_hook_handle) {
            uc_hook_del(uc_, pending.return_hook_handle);
        }
    }
    pending_returns_.clear();
}
