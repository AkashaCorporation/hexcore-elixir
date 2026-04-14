# Clean-Room Policy for HexCore Elixir

## Why this matters

HexCore Elixir is **Apache-2.0** licensed. Its upstream reference implementation (`hexcore-debugger/` in the HexCore monorepo) is MIT. Every file in `handoff/specs/` was extracted from the MIT monorepo. **Reading them is safe. Copying from them verbatim is not.**

The clean-room discipline exists for three reasons:
1. **License purity** — Apache-2.0 downstream consumers should not have to audit Elixir's provenance for hidden MIT/GPL lineage.
2. **Defensible origination** — if someone later claims Elixir is a derivative work, the git history and clean-room policy provide the rebuttal.
3. **Architectural discipline** — forcing re-derivation from spec catches bugs-by-copy-paste and produces cleaner abstractions than a port.

## What you can do

| Action | Allowed? |
|---|---|
| Read any file in `handoff/specs/` | ✅ |
| Read `deps/hexcore-unicorn/src/unicorn_wrapper.cpp` and friends | ✅ (reference wrapper) |
| Read `deps/hexcore-unicorn/test/*.js` | ✅ (test reference) |
| Read Unicorn upstream headers in `deps/hexcore-unicorn/include/unicorn/` | ✅ |
| Read the Microsoft PE spec, ELF spec, Apple Mach-O docs, MSDN, man pages | ✅ |
| Read frida-gum source (wxWindows-style permissive license — check each file) | ✅ with caveat: note the source in your PR description |
| Read DynamoRIO papers (BSD-3) | ✅ |
| Read Qiling source | ❌ — GPLv3, keep Elixir clean |
| Read Frida-core or frida-tools source | ❌ — GPL |

## What you must not do

| Action | Forbidden |
|---|---|
| Copy a function body verbatim from `hexcore-debugger/` TypeScript | ❌ |
| Copy a C++ function from `unicorn_wrapper.cpp` verbatim | ❌ |
| Lift identifier names or comments from the reference implementation | ❌ |
| Reuse `static bool InvalidMemHookCB(uc_engine* uc, ...)` as the exact signature of your own callback | ❌ (different signature is fine — different name + shape) |
| Translate a TypeScript file to Rust line-by-line keeping the same structure | ❌ |

## What you should do

1. **Read the spec**, understand the *behavior* being described, then **close the spec** and write the implementation.
2. Implement in your own style: idiomatic Rust where possible, idiomatic C++23 where C++ is needed, own naming conventions, own comment style.
3. When in doubt: **paraphrase, don't copy**. If two independent engineers would both name a variable `fault_address`, that's fine. If you find yourself copying 5 lines of context to preserve behavior, stop and re-derive.

## How to cite your work

Every file in `engine/src/`, `crates/elixir-core/src/`, and `agents/src/` should include a top comment like:

```cpp
// HexCore Elixir — <Component>
//
// Clean-room derivation from:
//   - Microsoft PE specification (PE32+ Windows x64 image format)
//   - hexcore-debugger/peLoader.ts (reference behavior for data import blocks)
//   - handoff/specs/data-import-detection.md (this repo, see CLEAN_ROOM.md)
//
// Apache-2.0 licensed. No code was copied verbatim from the references above.
```

This establishes the paper trail for license audit and gives future maintainers the context to re-derive.

## Red flags to catch in your own work

Before submitting a PR, ask yourself:
- Am I comfortable defending this code as independently written?
- If someone diffed my file against `peLoader.ts` or `winApiHooks.ts`, would the similarity look like "two engineers solving the same problem" or "one engineer translating another's code"?
- Did I copy a structural pattern (e.g. the exact sequence of offset writes in `setupTebPeb`) without adding my own architectural layer on top?

If any of those questions make you uncomfortable, rewrite from the spec.

## The gate

All PRs touching `engine/`, `crates/`, or `agents/` require a `LICENSE_AUDIT:` line in the description listing every reference consulted. PRs without this line are rejected.

---

**When in doubt, ask the spec, not the reference implementation.** The specs in this directory are the source of truth for behavior. They exist so you never need to open the reference implementation at all.
