// HexCore Elixir — Windows Registry Emulation
//
// Fake registry backed by VFS. Supports RegOpenKey, RegQueryValue, etc.
// Used by malware and packers that check registry keys for anti-analysis.

#include "elixir/elixir.h"

// TODO: Implement registry emulation
// - In-memory tree of HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, etc.
// - Pre-populated with common anti-debug check keys
// - NtOpenKey, NtQueryValueKey, NtSetValueKey handlers
