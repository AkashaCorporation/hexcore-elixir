// HexCore Elixir — Win32 API Hook Table
//
// Clean-room implementation. No code copied verbatim.
// Apache-2.0 licensed.

#pragma once

#include "elixir.h"  // for ElixirStopReason
#include <cstdint>
#include <string>
#include <map>
#include <unordered_map>
#include <vector>
#include <functional>
#include <unicorn/unicorn.h>

class MemoryManager;

struct ImportEntry;  // forward declare, defined in engine_internal.h
struct ElixirContext;  // forward declare, defined in engine_internal.h

using ApiHandlerFn = std::function<uint64_t(uc_engine*, MemoryManager*, const std::vector<uint64_t>&)>;

// One record per hooked Win32 call. Populated by code_hook_callback in
// api_hooks.cpp on every guest -> stub dispatch. Consumed by the FFI
// surface via elixir_api_log_to_json, which serialises the vector into
// a JSON payload that the Rust layer deserialises into ApiLogEntry.
struct ApiLogEntry {
    std::string name;            // import function name (e.g. "GetSystemTimeAsFileTime")
    std::string module;          // source DLL as declared in IAT (empty for dynamic stubs)
    uint64_t pc_address;         // stub address where the hook fired
    std::vector<uint64_t> args;  // first N args captured via read_args
    uint64_t return_value;       // what the handler returned (also what RAX holds)
};

class Win32HookTable {
    uc_engine* uc_;
    MemoryManager* mem_;
    ElixirContext* ctx_ = nullptr;  // for stop_reason access in exit handlers
    uc_hook code_hook_handle_ = 0;
    
    std::map<uint64_t, ApiHandlerFn> handlers_;
    std::map<std::string, ApiHandlerFn> named_handlers_;
    std::map<uint64_t, ImportEntry*> stub_to_import_;
    
    // Handler name lookup (for logging)
    std::map<uint64_t, std::string> stub_to_name_;
    // Source DLL per stub address (populated by register_pe_imports).
    // Dynamic stubs synthesised by GetProcAddress are intentionally absent:
    // they have no single IAT origin so the log's module stays empty for them.
    std::map<uint64_t, std::string> stub_to_module_;
    
    // State
    uint64_t tick_counter_ = 0;
    uint64_t perf_counter_ = 0;
    uint64_t crt_data_ptr_ = 0;
    uint64_t image_base_ = 0;
    std::map<uint64_t, std::string> module_handles_;
    uint64_t next_handle_ = 0x80000000;
    
    // VirtualAlloc tracking (addr -> size)
    std::unordered_map<uint64_t, uint64_t> virtual_allocs_;
    uint64_t next_virtual_addr_ = 0x20000000;
    
    // Default process heap handle
    uint64_t process_heap_handle_ = 0xAA0000;
    
    // API call log
    std::vector<ApiLogEntry> api_log_;
    
    static void code_hook_callback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    
    // Internal helpers
    uint64_t read_reg(int regid);
    void write_reg(int regid, uint64_t value);
    uint64_t read_stack_arg(int index);  // index 0 = 5th arg at [rsp+0x28], etc.
    std::vector<uint64_t> read_args(int count);
    void do_return(uint64_t retval);
    
    void ensure_crt_data_allocated();
    
public:
    Win32HookTable(uc_engine* uc, MemoryManager* mem, uint64_t image_base, ElixirContext* ctx = nullptr);
    ~Win32HookTable();
    
    void set_context(ElixirContext* ctx) { ctx_ = ctx; }
    
    void register_handler(const std::string& name, uint64_t stub_addr, ApiHandlerFn handler);
    void register_pe_imports(const std::vector<ImportEntry>& imports);
    void register_all_handlers();
    
    size_t api_log_count() const { return api_log_.size(); }
    const std::vector<ApiLogEntry>& api_log() const { return api_log_; }
};
