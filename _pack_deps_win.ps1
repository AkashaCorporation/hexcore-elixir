# ============================================================================
#  HexCore Elixir - Package vendored deps for CI consumption
#
#  Creates elixir-deps-win32-x64.zip containing the vendored hexcore-unicorn
#  (headers, import lib, runtime DLL) that the Elixir engine CMake build
#  needs. Mirrors the pattern of souper-source/_pack_deps_win.ps1 and
#  caps/add-engine-to-zip.ps1 (Helix).
#
#  Usage:
#    1. Ensure deps/hexcore-unicorn/ is populated locally (already vendored
#       per VERSION.md)
#    2. Run this script from the HexCore-Elixir root
#    3. Upload the produced zip to the v1.0.3 GitHub Release of
#       AkashaCorporation/HexCore-Elixir
#
#  After upload, the prebuild-elixir-windows job in the HexCore monorepo's
#  hexcore-native-prebuilds.yml workflow can download and consume it.
# ============================================================================

$ErrorActionPreference = "Stop"
$ROOT = $PSScriptRoot
$DEPS_SRC = "$ROOT\deps\hexcore-unicorn"
$OUTPUT_DIR = "$ROOT\elixir-deps-staging"
$ZIP_PATH = "$ROOT\elixir-deps-win32-x64.zip"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Packaging Elixir Vendored Deps"        -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ── Sanity checks ──────────────────────────────────────────────────────
if (-not (Test-Path $DEPS_SRC)) {
    Write-Error "Source deps directory not found: $DEPS_SRC"
    Write-Error "Populate it first (see deps/hexcore-unicorn/VERSION.md for provenance)."
    exit 1
}

$ENGINE_LIB = "$ROOT\engine\build\Release\elixir_engine.lib"

$requiredFiles = @(
    "$DEPS_SRC\bin\unicorn.dll",
    "$DEPS_SRC\lib\unicorn-import.lib",
    "$DEPS_SRC\include\unicorn\unicorn.h",
    $ENGINE_LIB
)

foreach ($f in $requiredFiles) {
    if (-not (Test-Path $f)) {
        Write-Error "Missing required file: $f"
        if ($f -eq $ENGINE_LIB) {
            Write-Error "Build the engine first:"
            Write-Error "  cmake -B engine/build -S engine -DCMAKE_BUILD_TYPE=Release"
            Write-Error "  cmake --build engine/build --config Release"
        }
        exit 1
    }
}

# ── Clean staging ──────────────────────────────────────────────────────
if (Test-Path $OUTPUT_DIR) { Remove-Item $OUTPUT_DIR -Recurse -Force }
if (Test-Path $ZIP_PATH) { Remove-Item $ZIP_PATH -Force }

# ── Stage only the essential files (exclude src/, binding.gyp, index.*,
#    package.json.reference, README.md.reference - those are reference-only
#    and not needed for CMake builds) ─────────────────────────────────
Write-Host "Staging essential files..." -ForegroundColor Yellow

New-Item -ItemType Directory -Force -Path "$OUTPUT_DIR\deps\hexcore-unicorn\include\unicorn" | Out-Null
New-Item -ItemType Directory -Force -Path "$OUTPUT_DIR\deps\hexcore-unicorn\lib" | Out-Null
New-Item -ItemType Directory -Force -Path "$OUTPUT_DIR\deps\hexcore-unicorn\bin" | Out-Null

Copy-Item "$DEPS_SRC\include\unicorn\*" "$OUTPUT_DIR\deps\hexcore-unicorn\include\unicorn\" -Recurse -Force
Copy-Item "$DEPS_SRC\lib\unicorn-import.lib" "$OUTPUT_DIR\deps\hexcore-unicorn\lib\" -Force
Copy-Item "$DEPS_SRC\bin\unicorn.dll" "$OUTPUT_DIR\deps\hexcore-unicorn\bin\" -Force

if (Test-Path "$DEPS_SRC\VERSION.md") {
    Copy-Item "$DEPS_SRC\VERSION.md" "$OUTPUT_DIR\deps\hexcore-unicorn\VERSION.md" -Force
}

# Pre-built Elixir engine static lib (consumed by Rust build.rs link search)
# Mirrors the Helix pattern where helix_engine.lib is bundled in the deps zip.
Write-Host "Staging pre-built elixir_engine.lib..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path "$OUTPUT_DIR\engine\build\Release" | Out-Null
Copy-Item $ENGINE_LIB "$OUTPUT_DIR\engine\build\Release\elixir_engine.lib" -Force
$libSize = [math]::Round((Get-Item $ENGINE_LIB).Length / 1MB, 2)
Write-Host "  elixir_engine.lib ($libSize MB)" -ForegroundColor DarkGray

# ── Size report ────────────────────────────────────────────────────────
Write-Host "" -ForegroundColor White
Write-Host "Staged contents:" -ForegroundColor Yellow
Get-ChildItem "$OUTPUT_DIR" -Recurse -File | ForEach-Object {
    $size = [math]::Round($_.Length / 1KB, 2)
    $rel = $_.FullName.Substring($OUTPUT_DIR.Length + 1)
    Write-Host "  $rel ($size KB)" -ForegroundColor DarkGray
}

# ── Create ZIP ────────────────────────────────────────────────────────
Write-Host "" -ForegroundColor White
Write-Host "Creating ZIP..." -ForegroundColor Yellow
Compress-Archive -Path "$OUTPUT_DIR\deps", "$OUTPUT_DIR\engine" -DestinationPath $ZIP_PATH -CompressionLevel Optimal

$zipSize = [math]::Round((Get-Item $ZIP_PATH).Length / 1MB, 2)
Write-Host "" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Done: $ZIP_PATH ($zipSize MB)" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. gh auth status  # verify auth" -ForegroundColor DarkGray
Write-Host "  2. gh release view v1.0.3 --repo AkashaCorporation/HexCore-Elixir" -ForegroundColor DarkGray
Write-Host "     (create it if it doesn't exist:" -ForegroundColor DarkGray
Write-Host "      gh release create v1.0.3 --repo AkashaCorporation/HexCore-Elixir --title 'v1.0.3 - VFS propagation')" -ForegroundColor DarkGray
Write-Host "  3. gh release upload v1.0.3 elixir-deps-win32-x64.zip --clobber --repo AkashaCorporation/HexCore-Elixir" -ForegroundColor DarkGray
Write-Host ""

# ── Cleanup staging dir ────────────────────────────────────────────────
Remove-Item $OUTPUT_DIR -Recurse -Force
