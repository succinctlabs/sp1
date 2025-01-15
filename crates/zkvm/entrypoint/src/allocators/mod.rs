//! Allocators for the SP1 zkVM.
//!
//! The `embedded` allocator takes precedence if enabled.

#[cfg(all(feature = "bump", not(feature = "embedded")))]
mod bump;

#[cfg(feature = "embedded")]
pub mod embedded;
