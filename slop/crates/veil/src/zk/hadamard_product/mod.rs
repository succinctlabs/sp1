mod prover;
mod verifier;

pub use prover::*;
pub use verifier::*;

// Re-export pub(in crate::hadamard_product) items needed by verifier module
pub(in crate::zk::hadamard_product) use prover::{ZkHadamardProductProof, EVAL_SCHEDULE};

#[cfg(test)]
mod tests;
