// elixir-core build.rs
// Links against the C++23 engine static library built by CMake.
//
// Build flow:
//   cmake → engine/build/Release/elixir_engine.lib
//   build.rs tells rustc where to find it

fn main() {
    // Path to the pre-built engine library (built separately via CMake)
    let engine_dir = std::path::Path::new("../../engine/build/Release");

    if engine_dir.exists() {
        println!("cargo:rustc-link-search=native={}", engine_dir.display());
        println!("cargo:rustc-link-lib=static=elixir_engine");

        // C++ runtime (MSVC)
        #[cfg(target_os = "windows")]
        {
            println!("cargo:rustc-link-lib=dylib=msvcrt");
        }

        // C++ runtime (Linux/macOS)
        #[cfg(not(target_os = "windows"))]
        {
            println!("cargo:rustc-link-lib=dylib=stdc++");
        }
    } else {
        println!("cargo:warning=Engine library not found at {:?} — building without C++ engine", engine_dir);
        println!("cargo:warning=Run: cmake -B engine/build -S engine -DCMAKE_BUILD_TYPE=Release && cmake --build engine/build --config Release");
    }
}
