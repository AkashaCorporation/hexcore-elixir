// HexCore Elixir — Windows Syscall Handlers (NTDLL layer)
//
// Clean-room implementation of Windows NT syscall emulation.
// These are the Nt* / Zw* functions that ntdll.dll dispatches via syscall.
//
// Reference: MSDN (public), ReactOS (LGPL — study behavior only, no code copy)

#include "elixir/elixir.h"

// TODO: Implement NT syscall dispatch
// Priority:
//   NtAllocateVirtualMemory, NtFreeVirtualMemory, NtProtectVirtualMemory
//   NtReadVirtualMemory, NtWriteVirtualMemory
//   NtCreateFile, NtReadFile, NtWriteFile, NtClose
//   NtQueryInformationProcess, NtQueryInformationThread
//   NtQuerySystemInformation
//   NtCreateThread, NtTerminateThread
//   NtDelayExecution (Sleep)
//   NtQueryVirtualMemory
