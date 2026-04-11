// HexCore Elixir — PE Loader
//
// Parses PE32/PE32+ (Windows executables and DLLs).
// Maps sections, resolves imports (IAT), processes relocations,
// and sets up TLS callbacks.
//
// Reference: Microsoft PE/COFF Specification (public)
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

#include "elixir/elixir.h"

// TODO: Implement PE loader
// - Parse DOS header → PE signature → COFF header → Optional header
// - Map each section (.text, .data, .rdata, .rsrc, etc.)
// - Process import directory → build IAT with hook stubs
// - Apply base relocations if image not at preferred base
// - Handle TLS directory and callbacks
