// HexCore Elixir — Core Library
// Clean-room dynamic analysis & emulation engine
//
// This crate provides the Rust types, traits, and FFI boundary
// that bridge the C++23 engine to the NAPI layer.

pub mod error;
pub mod ffi;
pub mod types;
pub mod emulator;
pub mod loader;
pub mod os;
pub mod instrument;
pub mod snapshot;
