// HexCore Elixir — CLI Tool
//
// Usage:
//   elixir_tool run <binary> --os <linux|windows|macos> [--script agent.js] [--interactive]
//   elixir_tool info <binary>    (show format, arch, entry point, imports)
//   elixir_tool snapshot <file>  (inspect a saved snapshot)

#include "elixir/elixir.h"
#include <cstdio>
#include <cstdlib>

static void usage() {
    printf("HexCore Elixir CLI v0.1.0\n\n");
    printf("Usage:\n");
    printf("  elixir_tool run <binary> --os <linux|windows|macos> [options]\n");
    printf("  elixir_tool info <binary>\n");
    printf("\nOptions:\n");
    printf("  --script <path>     Load an instrumentation agent script\n");
    printf("  --interactive       Drop into shell at entry point\n");
    printf("  --arch <arch>       Override architecture (x86|x64|arm|arm64)\n");
    printf("  --timeout <ms>      Max emulation time in milliseconds\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 1;
    }

    // TODO: Parse arguments and invoke engine
    printf("[elixir] Engine not yet implemented — skeleton only\n");
    return 0;
}
