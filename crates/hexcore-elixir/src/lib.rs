// HexCore Elixir — NAPI-RS Bridge
//
// This crate exposes the Elixir emulation engine to Node.js / VS Code
// via NAPI-RS, following the same pattern as @hexcore/helix.

use napi_derive::napi;

#[napi]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// TODO: Expose Emulator, Interceptor, Stalker, Snapshot as JS classes
// Pattern: same as hexcore-helix/crates/hexcore-helix/src/engine.rs
//
// #[napi(js_name = "Emulator")]
// pub struct JsEmulator { inner: elixir_core::emulator::Emulator }
//
// #[napi]
// impl JsEmulator {
//     #[napi(constructor)]
//     pub fn new(config: JsEmulatorConfig) -> napi::Result<Self> { ... }
//
//     #[napi]
//     pub fn load(&mut self, data: Buffer) -> napi::Result<BigInt> { ... }
//
//     #[napi]
//     pub fn run(&mut self, start: BigInt, end: BigInt) -> napi::Result<JsStopReason> { ... }
// }
