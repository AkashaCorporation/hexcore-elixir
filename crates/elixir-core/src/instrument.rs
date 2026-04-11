// elixir_core — Instrumentation Layer
//
// Tier 4 (elixir_agent): The instrumentation bridge.
// Provides Frida-style APIs for hooking, tracing, and memory manipulation.
//
// Concepts inspired by:
//   - frida-gum (wxWindows license — permissive, OK to study)
//   - DynamoRIO (BSD-3-Clause — OK to study)
//   - Intel Pin papers (academic reference)
//
// NO CODE from Frida-core (GPLv3) or any GPL source.

use crate::error::ElixirResult;
use crate::types::HookType;

/// Interceptor — inline function hooking at the emulation layer
pub struct Interceptor {
    // TODO: hook table, trampoline management
}

impl Interceptor {
    pub fn new() -> Self {
        Self {}
    }

    /// Attach a hook to a function address
    pub fn attach(&mut self, _target: u64, _hook_type: HookType) -> ElixirResult<u64> {
        // Returns a hook ID
        todo!("interceptor attach")
    }

    /// Detach a previously installed hook
    pub fn detach(&mut self, _hook_id: u64) -> ElixirResult<()> {
        todo!("interceptor detach")
    }

    /// Replace a function entirely with a custom implementation
    pub fn replace(&mut self, _target: u64, _replacement: u64) -> ElixirResult<u64> {
        todo!("interceptor replace")
    }
}

/// Stalker — basic block level tracing (like Frida's Stalker)
pub struct Stalker {
    // TODO: trace buffer, block coverage set
}

impl Stalker {
    pub fn new() -> Self {
        Self {}
    }

    /// Start tracing execution from the current point
    pub fn follow(&mut self) -> ElixirResult<()> {
        todo!("stalker follow")
    }

    /// Stop tracing
    pub fn unfollow(&mut self) -> ElixirResult<()> {
        todo!("stalker unfollow")
    }

    /// Get the collected trace (list of basic block addresses)
    pub fn drain_trace(&mut self) -> Vec<u64> {
        todo!("stalker drain")
    }
}
