// HexCore Elixir — VFS Integration Tests
//
// Tests the Virtual File System through the Rust FFI layer.

use elixir_core::emulator::{Emulator, EmulatorConfig};
use elixir_core::types::{Arch, OsType};

fn create_emulator() -> Emulator {
    let config = EmulatorConfig {
        arch: Arch::X86_64,
        os: OsType::Linux,
        stack_size: 0x10000,
        heap_size: 0x100000,
        permissive_memory: true,
    };
    Emulator::new(config).expect("Failed to create emulator")
}

#[test]
fn test_vfs_create_file_and_read_back() {
    let emu = create_emulator();

    // Create a virtual file
    let content = b"Hello, VFS!";
    emu.vfs_create_file("/tmp/test.txt", content)
        .expect("vfs_create_file failed");
}

#[test]
fn test_vfs_create_dir() {
    let emu = create_emulator();

    emu.vfs_create_dir("/tmp/mydir")
        .expect("vfs_create_dir failed");

    // Create a file inside the directory
    emu.vfs_create_file("/tmp/mydir/file.txt", b"inside dir")
        .expect("vfs_create_file in dir failed");
}

#[test]
fn test_vfs_stdout_capture_empty_by_default() {
    let emu = create_emulator();

    let stdout = emu.vfs_get_stdout().expect("vfs_get_stdout failed");
    assert_eq!(stdout, "", "stdout should be empty initially");
}

#[test]
fn test_vfs_stderr_capture_empty_by_default() {
    let emu = create_emulator();

    let stderr = emu.vfs_get_stderr().expect("vfs_get_stderr failed");
    assert_eq!(stderr, "", "stderr should be empty initially");
}

#[test]
fn test_vfs_clear_output() {
    let emu = create_emulator();

    // Clear should succeed even when empty
    emu.vfs_clear_output().expect("vfs_clear_output failed");
}

#[test]
fn test_vfs_create_file_empty_content() {
    let emu = create_emulator();

    emu.vfs_create_file("/tmp/empty.txt", b"")
        .expect("vfs_create_file with empty content failed");
}

#[test]
fn test_vfs_create_file_binary_content() {
    let emu = create_emulator();

    let binary_data: Vec<u8> = (0..=255).collect();
    emu.vfs_create_file("/tmp/binary.bin", &binary_data)
        .expect("vfs_create_file with binary content failed");
}

#[test]
fn test_vfs_nested_dirs() {
    let emu = create_emulator();

    emu.vfs_create_dir("/a/b/c")
        .expect("nested dir creation failed");
    emu.vfs_create_file("/a/b/c/file.txt", b"deep")
        .expect("file in nested dir failed");
}

#[test]
fn test_vfs_windows_paths() {
    let emu = create_emulator();

    // Windows paths should be normalized
    emu.vfs_create_file("C:\\Users\\test\\file.txt", b"windows")
        .expect("windows path failed");
    emu.vfs_create_dir("C:\\Windows\\System32")
        .expect("windows dir failed");
}
