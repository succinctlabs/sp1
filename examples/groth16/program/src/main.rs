#![no_main]
sp1_zkvm::entrypoint!(main);

use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;

use lib::{
    SerdeSerializableInputs, SerdeSerializablePreparedVerifyingKey, SerdeSerializableProof,
    SerializableInputs, SerializablePreparedVerifyingKey, SerializableProof,
};

pub fn main() {
    let serializable_pvk = sp1_zkvm::io::read::<SerdeSerializablePreparedVerifyingKey>();
    let serializable_inputs = sp1_zkvm::io::read::<SerdeSerializableInputs>();
    let serializable_proof = sp1_zkvm::io::read::<SerdeSerializableProof>();

    let pvk = SerializablePreparedVerifyingKey::from(serializable_pvk).0;
    let inputs = SerializableInputs::from(serializable_inputs).0;
    let proof = SerializableProof::from(serializable_proof).0;

    let verified = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();

    sp1_zkvm::io::commit(&verified);
}
