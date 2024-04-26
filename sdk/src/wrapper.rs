use anyhow::Result;
pub use sp1_recursion_circuit::witness::Witnessable;
pub use sp1_recursion_compiler::ir::{Config, Witness};
pub use sp1_recursion_gnark_ffi::{Groth16Proof, Groth16Prover};
use std::path::PathBuf;

/// A client that can wrap proofs via Gnark.
#[derive(Debug, Clone)]
pub struct WrapperClient {
    pub prover: Groth16Prover,
}

impl WrapperClient {
    pub fn new(build_dir: PathBuf) -> Self {
        let prover = Groth16Prover::new(build_dir);
        Self { prover }
    }

    pub fn prove<C: Config>(&self, witness: Witness<C>) -> Result<Groth16Proof> {
        let wrapped_proof = self.prover.prove(witness.clone());
        Ok(wrapped_proof)
    }
}
