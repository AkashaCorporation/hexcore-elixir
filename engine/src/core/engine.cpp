// HexCore Elixir — Core Engine
//
// Clean-room implementation using:
//   - Unicorn Engine 2.0.1 C API (unicorn/unicorn.h)
//   - HexCore Elixir public API (elixir/elixir.h)
//
// Apache-2.0 licensed. No code copied verbatim.

#include "elixir/engine_internal.h"
#include <unicorn/x86.h>
#include <cstring>
#include <cstdio>

// RDTSC instruction hook - return progressive values to pass timing checks
static uint64_t rdtsc_counter = 0;
static void rdtsc_hook(uc_engine* uc, void* user_data) {
    (void)user_data;
    // Return progressive values in EDX:EAX (RAX on x64)
    // Increment by a small amount to simulate normal CPU timing
    rdtsc_counter += 1000;
    uint64_t rax = rdtsc_counter & 0xFFFFFFFF;
    uint64_t rdx = rdtsc_counter >> 32;
    uc_reg_write(uc, UC_X86_REG_RAX, &rax);
    uc_reg_write(uc, UC_X86_REG_RDX, &rdx);
}

// CPUID instruction hook - return values that pass anti-VM checks
// The malware checks bit 31 of ECX (hypervisor bit) - we return 0 to indicate no hypervisor
static void cpuid_hook(uc_engine* uc, void* user_data) {
    (void)user_data;
    
    uint64_t rax = 0, rcx = 0;
    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
    
    uint32_t leaf = (uint32_t)rax;
    uint32_t subleaf = (uint32_t)rcx;
    (void)subleaf;
    
    uint64_t rbx = 0, rdx = 0;
    
    switch (leaf) {
        case 0:  // Vendor string
            rbx = 0x756E6547;  // "Genu"
            rdx = 0x49656E69;  // "ineI"
            rcx = 0x6C65746E;  // "ntel"
            break;
        case 1:  // Processor info - clear hypervisor bit (bit 31 of ECX)
            rbx = 0x00000800;  // Brand index
            rcx = 0x00000000;  // No hypervisor bit (bit 31 = 0), no VMX
            rdx = 0x00000000;  // No x87
            break;
        case 0x80000000:  // Extended features
            rax = 0x80000008;  // Max extended leaf
            break;
        case 0x80000001:  // Extended processor info
            rcx = 0x00000000;  // No hypervisor
            rdx = 0x00000000;
            break;
        case 0x80000002:  // Processor brand string part 1
            rbx = 0x20202020;
            rcx = 0x20202020;
            rdx = 0x20202020;
            break;
        case 0x80000003:  // Processor brand string part 2
            rbx = 0x20202020;
            rcx = 0x20202020;
            rdx = 0x20202020;
            break;
        case 0x80000004:  // Processor brand string part 3
            rbx = 0x20202020;
            rcx = 0x20202020;
            rdx = 0x20202020;
            break;
        default:
            // Return zeros for unknown leaves
            rax = 0;
            rbx = 0;
            rcx = 0;
            rdx = 0;
            break;
    }
    
    uc_reg_write(uc, UC_X86_REG_RAX, &rax);
    uc_reg_write(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_write(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_write(uc, UC_X86_REG_RDX, &rdx);
}

static ElixirError uc_err_to_elixir(uc_err err) {
    if (err == UC_ERR_OK) return ELIXIR_OK;
    return ELIXIR_ERR_UNICORN;
}

extern "C" {

ElixirContext* elixir_create(ElixirArch arch, ElixirOs os) {
    auto* ctx = new ElixirContext{};
    ctx->arch = arch;
    ctx->os   = os;

    uc_arch uc_arch_type;
    uc_mode uc_mode_type;

    switch (arch) {
        case ELIXIR_ARCH_X86:
            uc_arch_type = UC_ARCH_X86;
            uc_mode_type = UC_MODE_32;
            break;
        case ELIXIR_ARCH_X86_64:
            uc_arch_type = UC_ARCH_X86;
            uc_mode_type = UC_MODE_64;
            break;
        case ELIXIR_ARCH_ARM:
            uc_arch_type = UC_ARCH_ARM;
            uc_mode_type = UC_MODE_ARM;
            break;
        case ELIXIR_ARCH_ARM64:
            uc_arch_type = UC_ARCH_ARM64;
            uc_mode_type = UC_MODE_ARM;
            break;
        default:
            delete ctx;
            return nullptr;
    }

    uc_err err = uc_open(uc_arch_type, uc_mode_type, &ctx->uc);
    if (err != UC_ERR_OK) {
        delete ctx;
        return nullptr;
    }

    // Initialize MemoryManager with 16MB heap
    ctx->mem = std::make_unique<MemoryManager>(ctx->uc, 16 * 1024 * 1024, false);

    // Create Interceptor and Stalker
    ctx->interceptor = std::make_unique<Interceptor>(ctx->uc, ctx->mem.get());
    ctx->stalker = std::make_unique<Stalker>(ctx->uc);
    
    // Add RDTSC hook for timing anti-debug detection
    uc_hook rdtsc_hook_handle;
    uc_hook_add(ctx->uc, &rdtsc_hook_handle, UC_HOOK_INSN, 
                (void*)rdtsc_hook, ctx, 1, 0, UC_X86_INS_RDTSC);
    // Note: We intentionally don't store rdtsc_hook_handle - it's cleaned up with uc_close
    (void)rdtsc_hook_handle;
    
    // Add CPUID hook for anti-VM detection bypass
    uc_hook cpuid_hook_handle;
    uc_hook_add(ctx->uc, &cpuid_hook_handle, UC_HOOK_INSN,
                (void*)cpuid_hook, ctx, 1, 0, UC_X86_INS_CPUID);
    (void)cpuid_hook_handle;

    return ctx;
}

void elixir_destroy(ElixirContext* ctx) {
    if (!ctx) return;
    // Destroy in correct order: interceptor -> stalker -> linux_stubs -> linux_syscalls -> win32_hooks -> mem -> uc_close
    // interceptor uses stalker hooks, so it must be destroyed first
    ctx->interceptor.reset();
    // stalker uses uc hooks, destroy before linux_stubs, linux_syscalls and win32_hooks
    ctx->stalker.reset();
    // linux_stubs uses uc hooks, destroy before mem
    ctx->linux_stubs.reset();
    // linux_syscalls uses uc hooks, destroy before mem
    ctx->linux_syscalls.reset();
    // win32_hooks uses mem and uc, so it must be destroyed before mem
    ctx->win32_hooks.reset();
    // MemoryManager must be destroyed before uc_close (it needs uc for hook removal)
    ctx->mem.reset();
    if (ctx->uc) {
        uc_close(ctx->uc);
    }
    delete ctx;
}

ElixirError elixir_load(ElixirContext* ctx, const uint8_t* data, size_t len, uint64_t* out_entry) {
    if (!ctx || !data || len == 0 || !out_entry) return ELIXIR_ERR_ARGS;
    
    BinaryFormat fmt = detect_format(data, static_cast<uint64_t>(len));
    
    ElixirError err;
    uint64_t image_base = 0;
    
    switch (fmt) {
        case BinaryFormat::PE:
            err = pe_load(ctx, data, static_cast<uint64_t>(len), out_entry, &ctx->imports, &image_base);
            if (err == ELIXIR_OK && ctx->os == ELIXIR_OS_WINDOWS) {
                // Store the actual image base in context
                ctx->image_base = image_base;
                
                // Setup Windows process environment (TEB/PEB)
                err = setup_windows_process_env(ctx->uc, ctx->mem.get(),
                                                image_base,
                                                0x7FFF0000, 0x100000);
                
                // Create Win32HookTable and register handlers
                if (err == ELIXIR_OK) {
                    ctx->win32_hooks = std::make_unique<Win32HookTable>(ctx->uc, ctx->mem.get(), image_base, ctx);
                    ctx->win32_hooks->register_all_handlers();
                    ctx->win32_hooks->register_pe_imports(ctx->imports);
                }
            }
            return err;
        case BinaryFormat::ELF: {
            err = elf_load(ctx, data, static_cast<uint64_t>(len), out_entry);
            if (err == ELIXIR_OK && ctx->os == ELIXIR_OS_LINUX) {
                // Setup Linux process environment (stack, registers)
                setup_linux_process_env(ctx->uc, ctx->mem.get());
                
                // Install syscall handler for Linux
                ctx->linux_syscalls = std::make_unique<LinuxSyscallHandler>(ctx->uc, ctx->mem.get(), ctx);
                ctx->linux_syscalls->install_hook();
            }
            return err;
        }
        case BinaryFormat::MachO:
            return macho_load(ctx, data, static_cast<uint64_t>(len), out_entry);
        default:
            return ELIXIR_ERR_LOADER;
    }
}

ElixirError elixir_run(ElixirContext* ctx, uint64_t start, uint64_t end, uint64_t max_insns) {
    if (!ctx || !ctx->uc) return ELIXIR_ERR_ARGS;
    
    // Reset stop reason at start
    ctx->stop_reason = ELIXIR_STOP_NONE;
    
    uc_err err = uc_emu_start(ctx->uc, start, end, 0, max_insns);
    
    // Debug: print Unicorn error
    if (err != UC_ERR_OK) {
        printf("[ELIXIR] uc_emu_start failed: err=%d (%s) start=0x%llx\n",
               err, uc_strerror(err), (unsigned long long)start);
    }
    
    // Determine stop reason based on result
    if (ctx->stop_reason == ELIXIR_STOP_NONE) {
        if (err == UC_ERR_OK && max_insns > 0) {
            ctx->stop_reason = ELIXIR_STOP_INSN_LIMIT;
        } else if (err != UC_ERR_OK) {
            ctx->stop_reason = ELIXIR_STOP_ERROR;
        }
    }
    
    return uc_err_to_elixir(err);
}

ElixirError elixir_stop(ElixirContext* ctx) {
    if (!ctx || !ctx->uc) return ELIXIR_ERR_ARGS;
    ctx->stop_reason = ELIXIR_STOP_USER;
    uc_err err = uc_emu_stop(ctx->uc);
    return uc_err_to_elixir(err);
}

ElixirError elixir_mem_map(ElixirContext* ctx, uint64_t addr, uint64_t size, uint32_t prot) {
    if (!ctx || !ctx->mem) return ELIXIR_ERR_ARGS;

    uint32_t uc_prot = 0;
    if (prot & 1) uc_prot |= UC_PROT_READ;
    if (prot & 2) uc_prot |= UC_PROT_WRITE;
    if (prot & 4) uc_prot |= UC_PROT_EXEC;

    return ctx->mem->map(addr, size, uc_prot);
}

ElixirError elixir_mem_read(ElixirContext* ctx, uint64_t addr, uint8_t* buf, size_t len) {
    if (!ctx || !ctx->uc || !buf) return ELIXIR_ERR_ARGS;
    uc_err err = uc_mem_read(ctx->uc, addr, buf, len);
    return uc_err_to_elixir(err);
}

ElixirError elixir_mem_write(ElixirContext* ctx, uint64_t addr, const uint8_t* buf, size_t len) {
    if (!ctx || !ctx->uc || !buf) return ELIXIR_ERR_ARGS;
    uc_err err = uc_mem_write(ctx->uc, addr, buf, len);
    return uc_err_to_elixir(err);
}

ElixirError elixir_reg_read(ElixirContext* ctx, uint32_t reg_id, uint64_t* value) {
    if (!ctx || !ctx->uc || !value) return ELIXIR_ERR_ARGS;
    uc_err err = uc_reg_read(ctx->uc, reg_id, value);
    return uc_err_to_elixir(err);
}

ElixirError elixir_reg_write(ElixirContext* ctx, uint32_t reg_id, uint64_t value) {
    if (!ctx || !ctx->uc) return ELIXIR_ERR_ARGS;
    uc_err err = uc_reg_write(ctx->uc, reg_id, &value);
    return uc_err_to_elixir(err);
}

ElixirError elixir_snapshot_save(ElixirContext* ctx, uint8_t** out_data, size_t* out_len) {
    if (!ctx || !out_data || !out_len || !ctx->uc) return ELIXIR_ERR_ARGS;

    // 1. Save CPU context
    uc_context* uc_ctx = nullptr;
    uc_err err = uc_context_alloc(ctx->uc, &uc_ctx);
    if (err != UC_ERR_OK) return ELIXIR_ERR_UNICORN;

    err = uc_context_save(ctx->uc, uc_ctx);
    if (err != UC_ERR_OK) {
        uc_context_free(uc_ctx);
        return ELIXIR_ERR_UNICORN;
    }

    // Get context size
    size_t ctx_size = uc_context_size(ctx->uc);

    // 2. Collect memory regions
    const auto& regions = ctx->mem->regions();

    // 3. Calculate total size
    size_t total_size = 8 + 4 + 4 + 4;  // magic + version + arch + cpu_size
    total_size += ctx_size;               // cpu data
    total_size += 4;                      // region_count
    for (const auto& [base, region] : regions) {
        total_size += 8 + 8 + 4 + 4;    // base + size + prot + padding
        total_size += region.size;        // data
    }

    // 4. Allocate and serialize
    uint8_t* data = new uint8_t[total_size];
    size_t offset = 0;

    // Magic
    memcpy(data + offset, "ELXSNAP\0", 8); offset += 8;

    // Version
    uint32_t version = 1;
    memcpy(data + offset, &version, 4); offset += 4;

    // Arch
    uint32_t arch = (uint32_t)ctx->arch;
    memcpy(data + offset, &arch, 4); offset += 4;

    // CPU context size + data
    uint32_t cpu_size_32 = (uint32_t)ctx_size;
    memcpy(data + offset, &cpu_size_32, 4); offset += 4;
    memcpy(data + offset, uc_ctx, ctx_size); offset += ctx_size;

    // Region count
    uint32_t region_count = (uint32_t)regions.size();
    memcpy(data + offset, &region_count, 4); offset += 4;

    // Regions
    for (const auto& [base, region] : regions) {
        uint64_t r_base = region.base;
        uint64_t r_size = region.size;
        uint32_t r_prot = region.prot;
        uint32_t r_pad = 0;

        memcpy(data + offset, &r_base, 8); offset += 8;
        memcpy(data + offset, &r_size, 8); offset += 8;
        memcpy(data + offset, &r_prot, 4); offset += 4;
        memcpy(data + offset, &r_pad, 4); offset += 4;

        // Read memory data from Unicorn
        uc_mem_read(ctx->uc, r_base, data + offset, (size_t)r_size);
        offset += (size_t)r_size;
    }

    uc_context_free(uc_ctx);

    *out_data = data;
    *out_len = total_size;
    return ELIXIR_OK;
}

ElixirError elixir_snapshot_restore(ElixirContext* ctx, const uint8_t* data, size_t len) {
    if (!ctx || !data || !ctx->uc) return ELIXIR_ERR_ARGS;

    size_t offset = 0;

    // 1. Validate magic
    if (len < 20) return ELIXIR_ERR_ARGS;  // minimum header size
    if (memcmp(data, "ELXSNAP\0", 8) != 0) return ELIXIR_ERR_ARGS;
    offset += 8;

    // 2. Version
    uint32_t version;
    memcpy(&version, data + offset, 4); offset += 4;
    if (version != 1) return ELIXIR_ERR_ARGS;

    // 3. Arch
    uint32_t arch;
    memcpy(&arch, data + offset, 4); offset += 4;
    if (arch != (uint32_t)ctx->arch) return ELIXIR_ERR_ARGS;  // arch mismatch

    // 4. CPU context
    uint32_t cpu_size;
    memcpy(&cpu_size, data + offset, 4); offset += 4;
    if (offset + cpu_size > len) return ELIXIR_ERR_ARGS;

    // Allocate and restore CPU context
    uc_context* uc_ctx = nullptr;
    uc_err err = uc_context_alloc(ctx->uc, &uc_ctx);
    if (err != UC_ERR_OK) return ELIXIR_ERR_UNICORN;

    // Copy saved context data into the allocated context
    size_t actual_ctx_size = uc_context_size(ctx->uc);
    if (cpu_size != actual_ctx_size) {
        uc_context_free(uc_ctx);
        return ELIXIR_ERR_ARGS;  // size mismatch
    }
    memcpy(uc_ctx, data + offset, cpu_size);
    offset += cpu_size;

    err = uc_context_restore(ctx->uc, uc_ctx);
    uc_context_free(uc_ctx);
    if (err != UC_ERR_OK) return ELIXIR_ERR_UNICORN;

    // 5. Memory regions
    if (offset + 4 > len) return ELIXIR_ERR_ARGS;
    uint32_t region_count;
    memcpy(&region_count, data + offset, 4); offset += 4;

    for (uint32_t i = 0; i < region_count; i++) {
        if (offset + 24 > len) return ELIXIR_ERR_ARGS;  // 8+8+4+4 = 24

        uint64_t r_base, r_size;
        uint32_t r_prot, r_pad;
        memcpy(&r_base, data + offset, 8); offset += 8;
        memcpy(&r_size, data + offset, 8); offset += 8;
        memcpy(&r_prot, data + offset, 4); offset += 4;
        memcpy(&r_pad, data + offset, 4); offset += 4;

        if (offset + r_size > len) return ELIXIR_ERR_ARGS;

        // Try to map the region (may already exist)
        // Use uc_mem_map directly - if it fails because already mapped, that's OK
        uc_mem_map(ctx->uc, r_base, (size_t)r_size, r_prot);
        // Ignore error - region may already be mapped

        // Write the data
        err = uc_mem_write(ctx->uc, r_base, data + offset, (size_t)r_size);
        offset += (size_t)r_size;

        if (err != UC_ERR_OK) return ELIXIR_ERR_MEMORY;
    }

    return ELIXIR_OK;
}

void elixir_snapshot_free(uint8_t* data) {
    delete[] data;
}

ElixirError elixir_set_option(ElixirContext* ctx, int option, uint64_t value) {
    if (!ctx) return ELIXIR_ERR_ARGS;
    switch (option) {
        case ELIXIR_OPT_PERMISSIVE_MEMORY:
            if (ctx->mem) ctx->mem->set_permissive(value != 0);
            return ELIXIR_OK;
        default:
            return ELIXIR_ERR_ARGS;
    }
}

uint64_t elixir_api_log_count(ElixirContext* ctx) {
    if (!ctx || !ctx->win32_hooks) return 0;
    return static_cast<uint64_t>(ctx->win32_hooks->api_log_count());
}

// --- Stop Reason ---
ElixirStopReason elixir_get_stop_reason(ElixirContext* ctx) {
    if (!ctx) return ELIXIR_STOP_NONE;
    return ctx->stop_reason;
}

// --- Interceptor C API ---
ElixirError elixir_interceptor_attach(ElixirContext* ctx, uint64_t addr) {
    if (!ctx || !ctx->interceptor) return ELIXIR_ERR_ARGS;
    ctx->interceptor->attach(addr);
    return ELIXIR_OK;
}

ElixirError elixir_interceptor_detach(ElixirContext* ctx, uint64_t addr) {
    if (!ctx || !ctx->interceptor) return ELIXIR_ERR_ARGS;
    ctx->interceptor->detach(addr);
    return ELIXIR_OK;
}

uint64_t elixir_interceptor_log_count(ElixirContext* ctx) {
    if (!ctx || !ctx->interceptor) return 0;
    return static_cast<uint64_t>(ctx->interceptor->log_count());
}

// --- Stalker C API ---
ElixirError elixir_stalker_follow(ElixirContext* ctx) {
    if (!ctx || !ctx->stalker) return ELIXIR_ERR_ARGS;
    ctx->stalker->follow();
    return ELIXIR_OK;
}

ElixirError elixir_stalker_unfollow(ElixirContext* ctx) {
    if (!ctx || !ctx->stalker) return ELIXIR_ERR_ARGS;
    ctx->stalker->unfollow();
    return ELIXIR_OK;
}

uint64_t elixir_stalker_block_count(ElixirContext* ctx) {
    if (!ctx || !ctx->stalker) return 0;
    return ctx->stalker->block_count();
}

ElixirError elixir_stalker_export_drcov(ElixirContext* ctx, uint8_t** out_data, size_t* out_len) {
    if (!ctx || !ctx->stalker || !out_data || !out_len) return ELIXIR_ERR_ARGS;
    auto drcov = ctx->stalker->export_drcov(ctx->image_base, 0x1000000, "module");
    *out_len = drcov.size();
    *out_data = new uint8_t[drcov.size()];
    memcpy(*out_data, drcov.data(), drcov.size());
    return ELIXIR_OK;
}

} // extern "C"
