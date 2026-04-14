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
    src/os/linux/linux_stubs.cpp
    src/os/windows/syscalls.cpp
    src/os/windows/process.cpp
    src/os/windows/registry.cpp
    src/os/windows/api_hooks.cpp
    src/instrument/interceptor.cpp
    src/instrument/stalker.cpp
    src/vfs/vfs.cpp
)

# --- Static library (linked by Rust via build.rs) ---
add_library(elixir_engine STATIC ${ENGINE_SOURCES})
target_include_directories(elixir_engine PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# --- HexCore-Unicorn (vendored dev dependency) ---
#
# See ../deps/hexcore-unicorn/VERSION.md for provenance.
# Layout of the vendor:
#   deps/hexcore-unicorn/include/unicorn/*.h   — Unicorn 2.0.1 C API headers
#   deps/hexcore-unicorn/lib/unicorn-import.lib — Windows import library
#   deps/hexcore-unicorn/bin/unicorn.dll       — runtime dynamic library
#
# When Elixir ships to the HexCore monorepo (Phase 5), delete the vendor and
# replace this block with a proper package manager dependency on
# `hexcore-unicorn@^1.2.3`. The include path and API surface will be identical.
set(HEXCORE_UNICORN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../deps/hexcore-unicorn")

if(EXISTS "${HEXCORE_UNICORN_DIR}/include/unicorn/unicorn.h")
    target_include_directories(elixir_engine PUBLIC
        ${HEXCORE_UNICORN_DIR}/include
    )
    message(STATUS "Elixir: using vendored hexcore-unicorn at ${HEXCORE_UNICORN_DIR}")

    if(WIN32 AND EXISTS "${HEXCORE_UNICORN_DIR}/lib/unicorn-import.lib")
        target_link_libraries(elixir_engine PUBLIC
            ${HEXCORE_UNICORN_DIR}/lib/unicorn-import.lib
        )

    endif()
else()
    message(WARNING "Elixir: hexcore-unicorn vendor not found at ${HEXCORE_UNICORN_DIR}")
    message(WARNING "  Expected: deps/hexcore-unicorn/include/unicorn/unicorn.h")
    message(WARNING "  Run from the Elixir repo root: see deps/hexcore-unicorn/VERSION.md")
endif()

# --- CLI tool ---
if(ELIXIR_BUILD_CLI)
    add_executable(elixir_tool tools/elixir_tool.cpp)
    target_link_libraries(elixir_tool PRIVATE elixir_engine)

    # Copy unicorn.dll next to the built elixir_tool so it runs out of the box.
    if(EXISTS "${HEXCORE_UNICORN_DIR}/bin/unicorn.dll")
        add_custom_command(TARGET elixir_tool POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${HEXCORE_UNICORN_DIR}/bin/unicorn.dll"
                "$<TARGET_FILE_DIR:elixir_tool>/unicorn.dll"
            COMMENT "Copying unicorn.dll runtime to elixir_tool output directory"
        )
    endif()
endif()

# --- Tests ---
if(ELIXIR_BUILD_TESTS)
    add_subdirectory(test)
endif()
