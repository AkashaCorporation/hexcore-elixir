// HexCore Elixir — Stalker
//
// Basic block tracing engine. Records every basic block executed
// during emulation — equivalent to Frida's Stalker but implemented
// at the Unicorn hook layer (UC_HOOK_BLOCK).
//
// Concept reference: frida-gum Stalker (wxWindows license)
// Concept reference: DynamoRIO basic block traces (BSD)

#include "elixir/elixir.h"

// TODO: Implement Stalker
// - follow() → installs UC_HOOK_BLOCK globally, records (addr, size) tuples
// - unfollow() → removes hook, returns trace
// - Configurable: record mode (basic blocks only, or instructions too)
// - Trace buffer: pre-allocated ring buffer to minimize allocation overhead
// - Coverage export: DRCOV format for Lighthouse/IDA/Ghidra integration
