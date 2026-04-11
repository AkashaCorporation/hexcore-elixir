cmake_minimum_required(VERSION 3.20)
project(elixir_engine LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Options ---
option(ELIXIR_BUILD_CLI    "Build the elixir_tool CLI"     ON)
option(ELIXIR_BUILD_TESTS  "Build engine tests"            OFF)

# --- Sources ---
set(ENGINE_SOURCES
    src/core/engine.cpp
    src/core/memory.cpp
    src/loader/pe_loader.cpp
    src/loader/elf_loader.cpp
    src/loader/macho_loader.cpp
    src/loader/format_detect.cpp
    src/os/linux/syscalls.cpp
    src/os/linux/process.cpp
    src/os/windows/syscalls.cpp
    src/os/windows/process.cpp
    src/os/windows/registry.cpp
    src/instrument/interceptor.cpp
    src/instrument/stalker.cpp
    src/vfs/vfs.cpp
)

# --- Static library (linked by Rust via build.rs) ---
add_library(elixir_engine STATIC ${ENGINE_SOURCES})
target_include_directories(elixir_engine PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# HexCore-Unicorn headers (populated by deps/ or git submodule)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/deps/unicorn/include")
    target_include_directories(elixir_engine PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/unicorn/include
    )
endif()

# --- CLI tool ---
if(ELIXIR_BUILD_CLI)
    add_executable(elixir_tool tools/elixir_tool.cpp)
    target_link_libraries(elixir_tool PRIVATE elixir_engine)
endif()

# --- Tests ---
if(ELIXIR_BUILD_TESTS)
    add_subdirectory(test)
endif()
