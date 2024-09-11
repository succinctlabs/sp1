#[cfg(feature = "verify-groth16")]
use groth16::{
    load_groth16_proof_from_bytes, load_groth16_verifying_key_from_bytes, verify_groth16,
};
#[cfg(feature = "verify-plonk")]
use plonk::{load_plonk_proof_from_bytes, load_plonk_verifying_key_from_bytes, verify_plonk};

mod constants;
mod converter;
mod groth16;
mod hash_to_field;
mod plonk;
mod transcript;

pub trait Verifier {
    type Fr;

    fn verify(proof: &[u8], vk: &[u8], public_inputs: &[Self::Fr]) -> bool;
}

#[cfg(feature = "verify-groth16")]
pub struct Groth16Verifier;

#[cfg(feature = "verify-groth16")]
impl Verifier for Groth16Verifier {
    type Fr = bn::Fr;

    fn verify(proof: &[u8], vk: &[u8], public_inputs: &[Self::Fr]) -> bool {
        let proof = load_groth16_proof_from_bytes(proof).unwrap();
        let vk = load_groth16_verifying_key_from_bytes(vk).unwrap();

        match verify_groth16(&vk, &proof, public_inputs) {
            Ok(result) => result,
            Err(e) => {
                println!("Error: {:?}", e);
                false
            }
        }
    }
}

#[cfg(feature = "verify-plonk")]
pub struct PlonkVerifier;

#[cfg(feature = "verify-plonk")]
impl Verifier for PlonkVerifier {
    type Fr = bn::Fr;

    fn verify(proof: &[u8], vk: &[u8], public_inputs: &[Self::Fr]) -> bool {
        let proof = load_plonk_proof_from_bytes(proof).unwrap();
        let vk = load_plonk_verifying_key_from_bytes(vk).unwrap();

        match verify_plonk(&vk, &proof, public_inputs) {
            Ok(result) => result,
            Err(_) => false,
        }
    }
}
