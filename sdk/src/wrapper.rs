use anyhow::Result;
use sp1_recursion_compiler::ir::{Config, Witness};
use sp1_recursion_gnark_ffi::{Groth16Proof, Groth16Prover};

/// A client that can wrap proofs via Gnark.
pub struct WrapperClient {
	pub prover: Groth16Prover,
}

impl WrapperClient {
	pub fn new(private_key: &str) -> Self {
        prover = Groth16Prover::new();
        Self { prover }
    }

	pub fn prove<C: Config>(&self, witness: Witness<C>) -> Result<Groth16Proof> {
        let wrapped_proof = self.prover.prove(witness.clone());
        Ok(wrapped_proof)
    }
}