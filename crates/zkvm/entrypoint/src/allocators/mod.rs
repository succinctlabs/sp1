//! Allocators for the SP1 zkVM.
//!
//! The `embedded` allocator takes precedence if enabled.

#[cfg(not(feature = "embedded"))]
mod bump;

#[cfg(feature = "embedded")]
pub mod embedded;

#[cfg(feature = "embedded")]
pub use embedded::init;
