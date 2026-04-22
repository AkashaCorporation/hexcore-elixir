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
#include <cstdint>
#include <exception>
#include <new>

#if defined(_WIN32)
#include <windows.h>
#endif

// FFI exception barrier. Every extern "C" function in this file MUST wrap its
// body in try { ... } catch with this macro so C++ exceptions never propagate
// across the Rust FFI boundary (which would be UB and silently abort the
// process — the exact symptom we hit inside the VS Code Extension Host when
// unicorn.dll had already been loaded by another extension and our allocator
// path diverged into a throwing branch).
#define ELIXIR_FFI_CATCH_RETURN(err_value) \
    catch (const std::bad_alloc& e) { \
        std::fprintf(stderr, "[elixir] %s: bad_alloc: %s\n", __func__, e.what()); \
        return (err_value); \
    } catch (const std::exception& e) { \
        std::fprintf(stderr, "[elixir] %s: %s\n", __func__, e.what()); \
        return (err_value); \
    } catch (...) { \
        std::fprintf(stderr, "[elixir] %s: unknown C++ exception\n", __func__); \
        return (err_value); \
    }

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

// SEH barrier around uc_emu_start.
//
// Why this exists and why /EHa + catch(...) isn't enough:
//
// Unicorn's libuc runs guest code through QEMU's TCG, which emits
// JIT-generated code at runtime. Those JIT blocks have no .pdata entries
// on x64 Windows — the OS exception unwinder cannot walk through them.
// When libuc faults with an access violation (e.g. stale TB pointer from
// a prior uc_engine instance in the same process, CPU state touched by a
// different consumer's thread, etc.), the structured exception propagates
// through those unannotated frames. MSVC's /EHa catch(...) relies on the
// C++ unwinder reaching the catch site by walking .pdata tables, and when
// it cannot it hands the fault to the unhandled exception filter which
// terminates the process — the exact symptom the VS Code Extension Host
// hit: silent death at uc_emu_start with no diagnostic.
//
// __try/__except uses the Windows SEH dispatcher directly (SetUnhandled-
// ExceptionFilter-style installation) and catches the fault before the
// C++ runtime is involved, regardless of intervening frames' unwind info.
//
// MSVC's C2712 rule forbids __try in a function that also owns C++
// objects with destructors, so this helper is intentionally minimal:
// only POD arguments, only POD locals, no STL types, no unique_ptr, no
// smart anything. Callers pass all state by value or raw pointer.
static uc_err seh_safe_uc_emu_start(uc_engine* uc,
                                     uint64_t begin,
                                     uint64_t until,
                                     uint64_t timeout,
                                     size_t count,
                                     uint32_t* out_seh_code) {
    uc_err result = UC_ERR_OK;
    *out_seh_code = 0;
#if defined(_WIN32)
    __try {
        result = uc_emu_start(uc, begin, until, timeout, count);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *out_seh_code = (uint32_t)GetExceptionCode();
        result = UC_ERR_EXCEPTION;
    }
#else
    // Non-Windows: no SEH. A fault in libuc here would deliver SIGSEGV
    // which we cannot recover from inside the process anyway.
    result = uc_emu_start(uc, begin, until, timeout, count);
#endif
    return result;
}

// Minimal JSON string escaper for api_log names/modules. API names come
// from PE IAT entries (pure ASCII in practice) and DLL names from the same
// source, so a full UTF-8 validator would be overkill — this handles the
// control chars and the two reserved punctuation marks that could break
// the parser on the Rust side (serde_json is strict about unescaped
// literals below 0x20).
static void json_escape_to(std::string& out, const std::string& s) {
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char tmp[8];
                    std::snprintf(tmp, sizeof(tmp), "\\u%04x", (unsigned)c);
                    out += tmp;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
}

extern "C" {

ElixirContext* elixir_create(ElixirArch arch, ElixirOs os) try {
    // Reset per-process static so successive emulations start from a
    // consistent RDTSC baseline.
    rdtsc_counter = 0;

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
            std::fprintf(stderr, "[elixir] elixir_create: unsupported arch=%d\n", (int)arch);
            return nullptr;
    }

    // Open Unicorn BEFORE allocating the context so a libuc failure never
    // leaves heap state behind.
    uc_engine* raw_uc = nullptr;
    uc_err err = uc_open(uc_arch_type, uc_mode_type, &raw_uc);
    if (err != UC_ERR_OK || raw_uc == nullptr) {
        std::fprintf(stderr, "[elixir] elixir_create: uc_open failed err=%d (%s)\n",
                     (int)err, uc_strerror(err));
        return nullptr;
    }

    // RAII guard for the uc engine. If any allocation below throws, the
    // guard closes the engine so we do not leak libuc state across retries.
    // On success we release() it into the context before returning.
    struct UcGuard {
        uc_engine* uc;
        ~UcGuard() { if (uc) uc_close(uc); }
        uc_engine* release() { auto* p = uc; uc = nullptr; return p; }
    } uc_guard{raw_uc};

    std::unique_ptr<ElixirContext> ctx(new (std::nothrow) ElixirContext{});
    if (!ctx) {
        std::fprintf(stderr, "[elixir] elixir_create: ctx allocation failed\n");
        return nullptr;  // uc_guard closes the engine
    }
    ctx->arch = arch;
    ctx->os = os;
    // Don't transfer ownership to ctx yet — do that only once all member
    // allocations have succeeded, so the guard covers exceptions during
    // MemoryManager / Interceptor / Stalker construction.
    ctx->uc = raw_uc;

    ctx->mem = std::make_unique<MemoryManager>(ctx->uc, 16 * 1024 * 1024, false);
    if (!ctx->mem) {
        std::fprintf(stderr, "[elixir] elixir_create: MemoryManager allocation failed\n");
        return nullptr;  // uc_guard + ctx unique_ptr clean up
    }

    ctx->interceptor = std::make_unique<Interceptor>(ctx->uc, ctx->mem.get());
    ctx->stalker = std::make_unique<Stalker>(ctx->uc);

    // Stack-local hook handles initialized to 0 so a failing uc_hook_add
    // never leaves a garbage value anywhere we might read later.
    uc_hook rdtsc_hook_handle = 0;
    uc_err rdtsc_err = uc_hook_add(ctx->uc, &rdtsc_hook_handle, UC_HOOK_INSN,
                                   (void*)rdtsc_hook, ctx.get(), 1, 0, UC_X86_INS_RDTSC);
    if (rdtsc_err != UC_ERR_OK) {
        std::fprintf(stderr, "[elixir] elixir_create: rdtsc hook_add failed err=%d (%s)\n",
                     (int)rdtsc_err, uc_strerror(rdtsc_err));
    }
    (void)rdtsc_hook_handle;

    uc_hook cpuid_hook_handle = 0;
    uc_err cpuid_err = uc_hook_add(ctx->uc, &cpuid_hook_handle, UC_HOOK_INSN,
                                   (void*)cpuid_hook, ctx.get(), 1, 0, UC_X86_INS_CPUID);
    if (cpuid_err != UC_ERR_OK) {
        std::fprintf(stderr, "[elixir] elixir_create: cpuid hook_add failed err=%d (%s)\n",
                     (int)cpuid_err, uc_strerror(cpuid_err));
    }
    (void)cpuid_hook_handle;

    // Flush any stale translation blocks left behind in libuc's process-global
    // TCG cache by a previous unicorn user (hexcore-debugger in the VS Code
    // Extension Host). Without this, our first uc_emu_start may dereference a
    // dangling pointer from a TB entry whose guest memory was freed when the
    // prior engine closed, and crash with 0xC0000005 — the symptom we hit.
    // Ignore the return value: on older libuc builds this ctl may not be
    // implemented, but failure is not fatal.
    uc_err flush_err = uc_ctl_flush_tb(ctx->uc);
    if (flush_err != UC_ERR_OK) {
        std::fprintf(stderr, "[elixir] elixir_create: uc_ctl_flush_tb returned %d (%s) — continuing\n",
                     (int)flush_err, uc_strerror(flush_err));
    } else {
        std::fprintf(stderr, "[elixir] elixir_create: flushed libuc TB cache\n");
    }
    std::fflush(stderr);

    // All allocations succeeded — release ownership from both guards.
    // Note: raw_uc is aliased inside ctx->uc, so we only "release" the guard
    // (which just nulls its pointer) and let elixir_destroy call uc_close
    // via ctx when the user disposes the engine.
    (void)uc_guard.release();
    return ctx.release();
}
ELIXIR_FFI_CATCH_RETURN(nullptr)

void elixir_destroy(ElixirContext* ctx) try {
    if (!ctx) return;

    if (ctx->tainted) {
        // libuc is in an undefined state after the SEH fault caught in
        // elixir_run. Running the MemoryManager / Interceptor / Stalker /
        // Win32HookTable destructors would trigger uc_hook_del calls that
        // dispatch into corrupted libuc code and re-fault — exactly the
        // symptom the Extension Host hit. Leak the entire context on this
        // path: the uc engine handle, the mem/hook/stalker subsystems, and
        // the ctx struct itself all stay allocated. The process survives;
        // memory is reclaimed at process exit. Disposing a tainted engine
        // is a recoverable-but-leaky operation, and Extension Host usage
        // is episodic enough that the leak is acceptable versus a crash.
        std::fprintf(stderr, "[elixir] elixir_destroy: ctx=%p is tainted, leaking the engine to avoid re-fault in libuc cleanup\n",
                     (void*)ctx);
        std::fflush(stderr);
        return;
    }

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
        ctx->uc = nullptr;
    }
    delete ctx;
} catch (const std::exception& e) {
    std::fprintf(stderr, "[elixir] elixir_destroy: %s\n", e.what());
} catch (...) {
    std::fprintf(stderr, "[elixir] elixir_destroy: unknown C++ exception\n");
}

ElixirError elixir_load(ElixirContext* ctx, const uint8_t* data, size_t len, uint64_t* out_entry) try {
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
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_LOADER)

ElixirError elixir_run(ElixirContext* ctx, uint64_t start, uint64_t end, uint64_t max_insns) try {
    // Step-by-step instrumentation with fflush on every line, so that when
    // we crash inside uc_emu_start (SEH access violation from a stale TB
    // cache entry, etc.) the Extension Host log still captures the exact
    // step at which we died. The /EHa build option lets the FFI catch
    // handler trap SEH faults too, but even if /EHa is not in effect on the
    // consumer side, these log lines pinpoint the crash site.
    std::fprintf(stderr, "[elixir] elixir_run: enter ctx=%p start=0x%llx end=0x%llx max_insns=%llu\n",
                 (void*)ctx,
                 (unsigned long long)start,
                 (unsigned long long)end,
                 (unsigned long long)max_insns);
    std::fflush(stderr);

    if (!ctx || !ctx->uc) {
        std::fprintf(stderr, "[elixir] elixir_run: bad args (ctx=%p uc=%p)\n",
                     (void*)ctx, (void*)(ctx ? ctx->uc : nullptr));
        std::fflush(stderr);
        return ELIXIR_ERR_ARGS;
    }

    // Reset stop reason at start
    ctx->stop_reason = ELIXIR_STOP_NONE;
    ctx->instruction_count = 0;

    // Flush libuc translation block cache a second time immediately before
    // uc_emu_start. The first flush happens at elixir_create; this one
    // covers the window between create and run during which an unrelated
    // unicorn user in the same process may have re-populated TCG state.
    // Any stale TB entry whose guest memory has been freed would crash the
    // next translation lookup, so we wipe the whole table.
    std::fprintf(stderr, "[elixir] elixir_run: uc_ctl_flush_tb pre-run\n");
    std::fflush(stderr);
    uc_err flush_err = uc_ctl_flush_tb(ctx->uc);
    if (flush_err != UC_ERR_OK) {
        std::fprintf(stderr, "[elixir] elixir_run: uc_ctl_flush_tb returned %d (%s) — continuing\n",
                     (int)flush_err, uc_strerror(flush_err));
        std::fflush(stderr);
    }

    // Install instruction counting hook. Initialize to 0 so a failing add
    // never leaves a garbage handle for the later uc_hook_del.
    std::fprintf(stderr, "[elixir] elixir_run: uc_hook_add UC_HOOK_CODE (count)\n");
    std::fflush(stderr);
    uc_hook count_hook = 0;
    uc_err add_err = uc_hook_add(ctx->uc, &count_hook, UC_HOOK_CODE,
        (void*)+[](uc_engine* /*uc*/, uint64_t /*addr*/, uint32_t /*size*/, void* user_data) {
            auto* c = static_cast<ElixirContext*>(user_data);
            c->instruction_count++;
        }, ctx, 1, 0);
    std::fprintf(stderr, "[elixir] elixir_run: uc_hook_add returned %d (%s) handle=%llu\n",
                 (int)add_err, uc_strerror(add_err), (unsigned long long)count_hook);
    std::fflush(stderr);
    if (add_err != UC_ERR_OK) {
        count_hook = 0;
    }

    std::fprintf(stderr, "[elixir] elixir_run: calling uc_emu_start (SEH-guarded) begin=0x%llx until=0x%llx timeout=0 count=%llu\n",
                 (unsigned long long)start,
                 (unsigned long long)end,
                 (unsigned long long)max_insns);
    std::fflush(stderr);

    // Route uc_emu_start through the SEH barrier. If libuc's JIT code
    // faults with a Windows access violation, seh_safe_uc_emu_start
    // catches it at the SEH dispatcher level — below C++ EH — and
    // returns a clean UC_ERR_EXCEPTION plus the raw NTSTATUS code.
    uint32_t seh_code = 0;
    uc_err err = seh_safe_uc_emu_start(ctx->uc, start, end, 0,
                                        (size_t)max_insns, &seh_code);

    if (seh_code != 0) {
        std::fprintf(stderr, "[elixir] elixir_run: SEH caught uc_emu_start fault 0x%08X (AV=%s) insns_executed=%llu\n",
                     (unsigned int)seh_code,
                     seh_code == 0xC0000005u ? "yes" : "no",
                     (unsigned long long)ctx->instruction_count);
        std::fflush(stderr);
    } else {
        std::fprintf(stderr, "[elixir] elixir_run: uc_emu_start returned %d (%s) insns_executed=%llu\n",
                     (int)err, uc_strerror(err),
                     (unsigned long long)ctx->instruction_count);
        std::fflush(stderr);
    }

    // Only remove counting hook if it was installed successfully.
    // Note: if the SEH fault corrupted libuc's hook table we might hit a
    // second fault here. The outer ELIXIR_FFI_CATCH_RETURN plus the fact
    // that uc_hook_del checks its arguments keeps this bounded.
    if (count_hook != 0 && seh_code == 0) {
        uc_hook_del(ctx->uc, count_hook);
    }

    // If we caught an SEH fault, treat the engine as tainted and return
    // ELIXIR_ERR_UC_FAULT. Callers that see this error must treat the
    // Emulator as unusable and destroy it — do not attempt further
    // uc_* calls on a faulted engine.
    if (seh_code != 0) {
        ctx->stop_reason = ELIXIR_STOP_ERROR;
        ctx->tainted = true;
        std::fprintf(stderr, "[elixir] elixir_run: returning ELIXIR_ERR_UC_FAULT (seh=0x%08X, ctx tainted)\n",
                     (unsigned int)seh_code);
        std::fflush(stderr);
        return ELIXIR_ERR_UC_FAULT;
    }

    // Determine stop reason based on result
    if (ctx->stop_reason == ELIXIR_STOP_NONE) {
        if (err == UC_ERR_OK && max_insns > 0) {
            ctx->stop_reason = ELIXIR_STOP_INSN_LIMIT;
        } else if (err != UC_ERR_OK) {
            ctx->stop_reason = ELIXIR_STOP_ERROR;
        }
    }

    std::fprintf(stderr, "[elixir] elixir_run: exit reason=%d err=%d\n",
                 (int)ctx->stop_reason, (int)err);
    std::fflush(stderr);

    return uc_err_to_elixir(err);
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_UNICORN)

ElixirError elixir_stop(ElixirContext* ctx) try {
    if (!ctx || !ctx->uc) return ELIXIR_ERR_ARGS;
    ctx->stop_reason = ELIXIR_STOP_USER;
    uc_err err = uc_emu_stop(ctx->uc);
    return uc_err_to_elixir(err);
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_UNICORN)

ElixirError elixir_mem_map(ElixirContext* ctx, uint64_t addr, uint64_t size, uint32_t prot) try {
    if (!ctx || !ctx->mem) return ELIXIR_ERR_ARGS;

    uint32_t uc_prot = 0;
    if (prot & 1) uc_prot |= UC_PROT_READ;
    if (prot & 2) uc_prot |= UC_PROT_WRITE;
    if (prot & 4) uc_prot |= UC_PROT_EXEC;

    return ctx->mem->map(addr, size, uc_prot);
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_MEMORY)

ElixirError elixir_mem_read(ElixirContext* ctx, uint64_t addr, uint8_t* buf, size_t len) try {
    if (!ctx || !ctx->uc || !buf) return ELIXIR_ERR_ARGS;
    if (ctx->tainted) return ELIXIR_ERR_UC_FAULT;
    uc_err err = uc_mem_read(ctx->uc, addr, buf, len);
    return uc_err_to_elixir(err);
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_MEMORY)

ElixirError elixir_mem_write(ElixirContext* ctx, uint64_t addr, const uint8_t* buf, size_t len) try {
    if (!ctx || !ctx->uc || !buf) return ELIXIR_ERR_ARGS;
    if (ctx->tainted) return ELIXIR_ERR_UC_FAULT;
    uc_err err = uc_mem_write(ctx->uc, addr, buf, len);
    return uc_err_to_elixir(err);
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_MEMORY)

ElixirError elixir_reg_read(ElixirContext* ctx, uint32_t reg_id, uint64_t* value) try {
    if (!ctx || !ctx->uc || !value) return ELIXIR_ERR_ARGS;
    if (ctx->tainted) {
        *value = 0;
        return ELIXIR_ERR_UC_FAULT;
    }
    uc_err err = uc_reg_read(ctx->uc, reg_id, value);
    return uc_err_to_elixir(err);
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_UNICORN)

ElixirError elixir_reg_write(ElixirContext* ctx, uint32_t reg_id, uint64_t value) try {
    if (!ctx || !ctx->uc) return ELIXIR_ERR_ARGS;
    if (ctx->tainted) return ELIXIR_ERR_UC_FAULT;
    uc_err err = uc_reg_write(ctx->uc, reg_id, &value);
    return uc_err_to_elixir(err);
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_UNICORN)

ElixirError elixir_snapshot_save(ElixirContext* ctx, uint8_t** out_data, size_t* out_len) try {
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
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_MEMORY)

ElixirError elixir_snapshot_restore(ElixirContext* ctx, const uint8_t* data, size_t len) try {
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
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_MEMORY)

void elixir_snapshot_free(uint8_t* data) try {
    delete[] data;
} catch (...) {
    std::fprintf(stderr, "[elixir] elixir_snapshot_free: unknown C++ exception\n");
}

ElixirError elixir_set_option(ElixirContext* ctx, int option, uint64_t value) try {
    if (!ctx) return ELIXIR_ERR_ARGS;
    switch (option) {
        case ELIXIR_OPT_PERMISSIVE_MEMORY:
            if (ctx->mem) ctx->mem->set_permissive(value != 0);
            return ELIXIR_OK;
        default:
            return ELIXIR_ERR_ARGS;
    }
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_ARGS)

uint64_t elixir_api_log_count(ElixirContext* ctx) try {
    if (!ctx || !ctx->win32_hooks) return 0;
    return static_cast<uint64_t>(ctx->win32_hooks->api_log_count());
}
ELIXIR_FFI_CATCH_RETURN(0)

ElixirError elixir_api_log_to_json(ElixirContext* ctx, uint8_t** out_data, size_t* out_len) try {
    if (!ctx || !out_data || !out_len) return ELIXIR_ERR_ARGS;
    if (ctx->tainted) return ELIXIR_ERR_UC_FAULT;

    // No hook table (e.g. ELF/Mach-O target) → emit an empty JSON array so
    // Rust's serde_json::from_slice always has something valid to parse.
    if (!ctx->win32_hooks) {
        static const char EMPTY[] = "[]";
        size_t n = sizeof(EMPTY) - 1;
        auto* data = new uint8_t[n];
        std::memcpy(data, EMPTY, n);
        *out_data = data;
        *out_len = n;
        return ELIXIR_OK;
    }

    const auto& log = ctx->win32_hooks->api_log();
    std::string buf;
    buf.reserve(log.size() * 128 + 2);
    buf.push_back('[');
    for (size_t i = 0; i < log.size(); ++i) {
        if (i) buf.push_back(',');
        const auto& e = log[i];
        buf += "{\"name\":\"";
        json_escape_to(buf, e.name);
        buf += "\",\"module\":\"";
        json_escape_to(buf, e.module);
        buf += "\",\"pc_address\":";
        buf += std::to_string(e.pc_address);
        buf += ",\"return_value\":";
        buf += std::to_string(e.return_value);
        buf += ",\"arguments\":[";
        for (size_t j = 0; j < e.args.size(); ++j) {
            if (j) buf.push_back(',');
            buf += std::to_string(e.args[j]);
        }
        buf += "]}";
    }
    buf.push_back(']');

    size_t n = buf.size();
    auto* data = new uint8_t[n];
    std::memcpy(data, buf.data(), n);
    *out_data = data;
    *out_len = n;
    return ELIXIR_OK;
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_UNICORN)

// --- Stop Reason ---
ElixirStopReason elixir_get_stop_reason(ElixirContext* ctx) try {
    if (!ctx) return ELIXIR_STOP_NONE;
    return ctx->stop_reason;
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_STOP_NONE)

// --- Interceptor C API ---
ElixirError elixir_interceptor_attach(ElixirContext* ctx, uint64_t addr) try {
    if (!ctx || !ctx->interceptor) return ELIXIR_ERR_ARGS;
    ctx->interceptor->attach(addr);
    return ELIXIR_OK;
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_UNICORN)

ElixirError elixir_interceptor_detach(ElixirContext* ctx, uint64_t addr) try {
    if (!ctx || !ctx->interceptor) return ELIXIR_ERR_ARGS;
    ctx->interceptor->detach(addr);
    return ELIXIR_OK;
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_UNICORN)

uint64_t elixir_interceptor_log_count(ElixirContext* ctx) try {
    if (!ctx || !ctx->interceptor) return 0;
    return static_cast<uint64_t>(ctx->interceptor->log_count());
}
ELIXIR_FFI_CATCH_RETURN(0)

// --- Project Pythia Oracle Hook: Breakpoint C API ---
// Persistent UC_HOOK_CODE that consults ctx->breakpoints on every instruction
// boundary. When PC matches, set stop_reason and call uc_emu_stop so the
// enclosing elixir_run returns cleanly. Guest state (RIP, GPRs, memory) is
// preserved; subsequent elixir_run from PC resumes naturally.
static void pythia_breakpoint_hook(uc_engine* uc, uint64_t addr, uint32_t /*size*/, void* user_data) {
    auto* ctx = static_cast<ElixirContext*>(user_data);
    if (!ctx) return;
    // std::unordered_set::count is O(1) average; acceptable per-instruction overhead.
    if (ctx->breakpoints.count(addr) > 0) {
        ctx->stop_reason = ELIXIR_STOP_BREAKPOINT;
        uc_emu_stop(uc);
    }
}

ElixirError elixir_breakpoint_add(ElixirContext* ctx, uint64_t addr) try {
    if (!ctx || !ctx->uc) return ELIXIR_ERR_ARGS;
    if (ctx->tainted) return ELIXIR_ERR_UC_FAULT;

    // Install the persistent BP hook on first use. A single hook handles
    // all breakpoints — checking the set is cheaper than hook bookkeeping.
    if (ctx->breakpoint_hook == 0) {
        uc_err err = uc_hook_add(ctx->uc, &ctx->breakpoint_hook, UC_HOOK_CODE,
                                  reinterpret_cast<void*>(pythia_breakpoint_hook),
                                  ctx, 1, 0);
        if (err != UC_ERR_OK) {
            ctx->breakpoint_hook = 0;
            std::fprintf(stderr, "[elixir] breakpoint_add: uc_hook_add failed %d (%s)\n",
                         (int)err, uc_strerror(err));
            std::fflush(stderr);
            return ELIXIR_ERR_UNICORN;
        }
    }

    ctx->breakpoints.insert(addr);
    return ELIXIR_OK;
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_UNICORN)

ElixirError elixir_breakpoint_del(ElixirContext* ctx, uint64_t addr) try {
    if (!ctx) return ELIXIR_ERR_ARGS;
    if (ctx->tainted) return ELIXIR_ERR_UC_FAULT;
    ctx->breakpoints.erase(addr);
    // We deliberately keep the hook installed — bp_check_hook is a no-op
    // when the set is empty, and this avoids racing hook add/del cycles.
    return ELIXIR_OK;
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_UNICORN)

ElixirError elixir_breakpoint_clear(ElixirContext* ctx) try {
    if (!ctx) return ELIXIR_ERR_ARGS;
    if (ctx->tainted) return ELIXIR_ERR_UC_FAULT;
    ctx->breakpoints.clear();
    return ELIXIR_OK;
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_UNICORN)

// --- Stalker C API ---
ElixirError elixir_stalker_follow(ElixirContext* ctx) try {
    if (!ctx || !ctx->stalker) return ELIXIR_ERR_ARGS;
    ctx->stalker->follow();
    return ELIXIR_OK;
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_UNICORN)

ElixirError elixir_stalker_unfollow(ElixirContext* ctx) try {
    if (!ctx || !ctx->stalker) return ELIXIR_ERR_ARGS;
    ctx->stalker->unfollow();
    return ELIXIR_OK;
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_UNICORN)

uint64_t elixir_stalker_block_count(ElixirContext* ctx) try {
    if (!ctx || !ctx->stalker) return 0;
    return ctx->stalker->block_count();
}
ELIXIR_FFI_CATCH_RETURN(0)

ElixirError elixir_stalker_export_drcov(ElixirContext* ctx, uint8_t** out_data, size_t* out_len) try {
    if (!ctx || !ctx->stalker || !out_data || !out_len) return ELIXIR_ERR_ARGS;
    auto drcov = ctx->stalker->export_drcov(ctx->image_base, 0x1000000, "module");
    *out_len = drcov.size();
    *out_data = new uint8_t[drcov.size()];
    memcpy(*out_data, drcov.data(), drcov.size());
    return ELIXIR_OK;
}
ELIXIR_FFI_CATCH_RETURN(ELIXIR_ERR_MEMORY)

// --- Instruction Count ---
uint64_t elixir_get_instruction_count(ElixirContext* ctx) try {
    if (!ctx) return 0;
    return ctx->instruction_count;
}
ELIXIR_FFI_CATCH_RETURN(0)

} // extern "C"
