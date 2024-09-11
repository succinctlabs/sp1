use anyhow::Result;
use bn::Fr;
use groth16_verifier::{Groth16Proof, Groth16VerifyingKey};

pub fn verify_groth16(
    vk: &Groth16VerifyingKey,
    proof: &Groth16Proof,
    public_inputs: &[Fr],
) -> Result<bool> {
    Ok(groth16_verifier::verify_groth16(vk, proof, public_inputs)?)
}
