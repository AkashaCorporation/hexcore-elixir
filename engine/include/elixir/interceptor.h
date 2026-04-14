// HexCore Elixir — Interceptor (Inline Hooks)
//
// Clean-room implementation using Unicorn Engine 2.0.1 UC_HOOK_CODE.
// Inspired by Frida Interceptor API pattern. No code copied verbatim.
//
// Apache-2.0 licensed.

#pragma once

#include <cstdint>
#include <string>
#include <map>
#include <vector>
#include <functional>
#include <stack>
#include <unicorn/unicorn.h>

class MemoryManager;

using InterceptorCallback = std::function<void(uc_engine*, uint64_t pc, const std::vector<uint64_t>& args)>;

struct InterceptorEntry {
    uint64_t target_addr;
    InterceptorCallback on_enter;
    InterceptorCallback on_leave;
    uc_hook hook_handle = 0;
};

class Interceptor {
    uc_engine* uc_;
    MemoryManager* mem_;
    std::map<uint64_t, InterceptorEntry> entries_;
    
    // Pending return hooks for onLeave
    struct PendingReturn {
        uint64_t target_addr;  // original attach address
        uint64_t return_addr;  // where the function will return to
        uc_hook return_hook_handle;
    };
    std::vector<PendingReturn> pending_returns_;
    
    // Log of intercepted calls
    struct InterceptLog {
        uint64_t addr;
        uint64_t retval;
    };
    std::vector<InterceptLog> log_;
    
    static void enter_hook_callback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    
    // Helper to read x64 args
    std::vector<uint64_t> read_args(int count);
    uint64_t read_reg(int regid);
    
public:
    Interceptor(uc_engine* uc, MemoryManager* mem);
    ~Interceptor();
    
    void attach(uint64_t addr, InterceptorCallback on_enter = nullptr, InterceptorCallback on_leave = nullptr);
    void detach(uint64_t addr);
    void detach_all();
    
    size_t log_count() const { return log_.size(); }
};
