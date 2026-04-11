// HexCore Elixir — Agent Runtime
//
// This module provides the Frida-style API surface for JS/TS agents.
// Agents are loaded by the Elixir engine and can hook functions,
// read/write memory, and manipulate registers mid-execution.

export { Interceptor } from './interceptor.js';
export { Stalker } from './stalker.js';
export { Memory } from './memory.js';
export { Process } from './process.js';
export type { InvocationContext, MemoryRange, ModuleInfo } from './types.js';
