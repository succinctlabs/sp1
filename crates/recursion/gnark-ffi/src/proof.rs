use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofBn254 {
    Plonk(PlonkBn254Proof),
    Groth16(Groth16Bn254Proof),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlonkBn254Proof {
    pub public_inputs: [String; 2],
    pub encoded_proof: String,
    pub raw_proof: String,
    pub plonk_vkey_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Groth16Bn254Proof {
    pub public_inputs: [String; 2],
    pub encoded_proof: String,
    pub raw_proof: String,
    pub groth16_vkey_hash: [u8; 32],
}
