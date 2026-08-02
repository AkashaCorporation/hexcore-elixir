// HexCore Elixir — Core Library
// Clean-room dynamic analysis & emulation engine
//
// This crate provides the Rust types, traits, and FFI boundary
// that bridge the C++23 engine to the NAPI layer.

pub mod emulator;
pub mod error;
pub mod ffi;
pub mod instrument;
pub mod loader;
pub mod os;
pub mod snapshot;
pub mod types;
