// HexCore Elixir — Interceptor
//
// Frida-style inline function hooking at the emulation layer.
// Since we control the CPU via Unicorn, hooking is done by installing
// code hooks at target addresses — no actual code patching needed.
//
// Concept reference: frida-gum (wxWindows license — permissive)
// Concept reference: DynamoRIO (BSD-3-Clause)

#include "elixir/elixir.h"

// TODO: Implement Interceptor
// - attach(target, onEnter, onLeave) → installs UC_HOOK_CODE at target
// - detach(hookId) → removes the hook
// - replace(target, replacement) → redirects execution to replacement address
// - InvocationContext: read/write args, retval, registers, thread ID
