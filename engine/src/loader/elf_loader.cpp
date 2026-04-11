// HexCore Elixir — ELF Loader
//
// Parses ELF32/ELF64 (Linux, Android, BSD).
// Maps PT_LOAD segments, processes dynamic linking (PLT/GOT),
// sets up the auxiliary vector, and handles TLS.
//
// Reference: ELF Specification (refspecs.linuxfoundation.org)

#include "elixir/elixir.h"

// TODO: Implement ELF loader
// - Parse ELF header → program headers → section headers
// - Map PT_LOAD segments with correct permissions
// - Process PT_DYNAMIC → DT_NEEDED, DT_SYMTAB, DT_STRTAB
// - Build PLT/GOT with hook stubs for imported functions
// - Set up stack: argc, argv, envp, auxv
// - Handle PT_TLS for thread-local storage
