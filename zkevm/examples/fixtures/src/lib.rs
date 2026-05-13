//! Vendored test vectors used by libzkevm's host-side example drivers.
//!
//! Each module owns the parsing for its respective fixture format and
//! exposes a flat list of typed cases. The cases are baked into the
//! crate via `include_str!` so runs don't depend on any filesystem
//! state.

pub mod eip196;
pub mod eip197;
pub mod eip198;
pub mod eip2537;
pub mod kzg;
pub mod wycheproof_ecdsa;
