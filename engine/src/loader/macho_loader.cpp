// HexCore Elixir — Mach-O Loader
//
// Parses Mach-O (macOS, iOS).
// Lower priority — stub for now.
//
// Reference: Apple Mach-O Programming Topics

#include "elixir/elixir.h"

// TODO: Implement Mach-O loader
// - Parse Mach-O header → load commands
// - Map LC_SEGMENT_64 segments
// - Process LC_DYLD_INFO_ONLY for imports
// - Handle LC_MAIN for entry point
