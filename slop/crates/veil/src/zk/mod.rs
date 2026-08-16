// `pub` so the benchmark targets under `benchmarking/` (which are external crates, unlike the
// in-tree `tests.rs`) can drive the dot-product protocol directly. Visibility widening only — the
// items themselves are unchanged.
pub mod dot_product;
pub mod error_correcting_code;
mod hadamard_product;
mod inner;
mod mask_counter;
mod prover_ctx;
mod verifier_ctx;

pub use inner::{ZkPcsProver, ZkPcsVerifier, ZkProof, ZkProveError};
pub use prover_ctx::ZkProverCtxInitError;
pub mod stacked_pcs;

pub use mask_counter::*;
pub use prover_ctx::*;
pub use verifier_ctx::*;
