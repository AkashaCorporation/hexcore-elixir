// elixir-core build.rs
//
// Links against:
//   1. `elixir_engine.lib`   — Elixir's C++23 engine, built separately via CMake
//   2. `unicorn-import.lib`  — Unicorn import library (vendored at deps/hexcore-unicorn/lib/)
//   3. `unicorn.dll`         — runtime DLL, copied next to the Rust output
//
// Build flow:
//   cmake → engine/build/Release/elixir_engine.lib
//   cargo build → consumes elixir_engine.lib via rustc-link-search below
//                 consumes unicorn via the vendored import lib
//                 copies unicorn.dll next to the produced .node / .exe
//
// When Elixir ships to the HexCore monorepo (Phase 5), replace the vendor
// references with a proper package-manager dependency on hexcore-unicorn 1.2.3+.

use std::path::Path;

fn main() {
    // --- 1. Elixir engine static library (from CMake) ---
    // CARGO_MANIFEST_DIR is the directory containing the Cargo.toml of this crate
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let crate_root = Path::new(&manifest_dir);
    let engine_dir = crate_root.join("../../engine/build/Release");
    if engine_dir.exists() {
        println!("cargo:rustc-link-search=native={}", engine_dir.display());
        println!("cargo:rustc-link-lib=static=elixir_engine");
    } else {
        println!("cargo:warning=Engine library not found at {:?} — build it first:", engine_dir);
        println!("cargo:warning=  cmake -B engine/build -S engine -DCMAKE_BUILD_TYPE=Release");
        println!("cargo:warning=  cmake --build engine/build --config Release");
    }

    // --- 2. Vendored hexcore-unicorn (import lib + DLL) ---
    // See deps/hexcore-unicorn/VERSION.md for provenance.
    let unicorn_lib_dir = crate_root.join("../../deps/hexcore-unicorn/lib");
    let unicorn_bin_dir = crate_root.join("../../deps/hexcore-unicorn/bin");

    if unicorn_lib_dir.exists() {
        println!("cargo:rustc-link-search=native={}", unicorn_lib_dir.display());
        // `unicorn-import.lib` is the Windows import library; it loads unicorn.dll at runtime.
        #[cfg(target_os = "windows")]
        {
            println!("cargo:rustc-link-lib=dylib=unicorn-import");
        }
    } else {
        println!("cargo:warning=Vendored hexcore-unicorn not found at {:?}", unicorn_lib_dir);
        println!("cargo:warning=See deps/hexcore-unicorn/VERSION.md");
    }

    // Copy unicorn.dll next to the Rust output so the built .node / .exe can find it.
    #[cfg(target_os = "windows")]
    if unicorn_bin_dir.exists() {
        let dll_src = unicorn_bin_dir.join("unicorn.dll");
        if let Ok(out_dir) = std::env::var("OUT_DIR") {
            // Climb out of `target/debug/build/elixir-core-XXXX/out` to `target/<profile>/deps/`
            let out_path = Path::new(&out_dir);
            if let Some(target_dir) = out_path.ancestors().nth(3) {
                let deps_dir = target_dir.join("deps");
                if deps_dir.exists() {
                    let dll_dst = deps_dir.join("unicorn.dll");
                    let _ = std::fs::copy(&dll_src, &dll_dst);
                }
            }
        }
    }

    // --- 3. Platform C++ runtime ---
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-lib=dylib=msvcrt");
    }
    #[cfg(not(target_os = "windows"))]
    {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }

    // Invalidate the build when key files change.
    println!("cargo:rerun-if-changed=../../engine/build/Release/elixir_engine.lib");
    println!("cargo:rerun-if-changed=../../deps/hexcore-unicorn/VERSION.md");
}
