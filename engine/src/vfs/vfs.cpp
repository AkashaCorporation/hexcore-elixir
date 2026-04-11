// HexCore Elixir — Virtual File System
//
// Fully isolated file system for emulated processes.
// Maps file operations (NtCreateFile / open) to an in-memory tree,
// with optional passthrough to host for specific paths.

#include "elixir/elixir.h"

// TODO: Implement VFS
// - In-memory directory tree
// - File descriptors / HANDLE table
// - Read/write/seek operations on virtual files
// - Pre-populated system files (C:\Windows\System32\*, /etc/*, /proc/*)
// - Optional host passthrough (e.g., map /tmp/target → real path)
// - Stat/fstat emulation
