use alloc::{boxed::Box, vec, vec::Vec};
use core::borrow::Borrow;

use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, PrimeField32, TwoAdicField};
use p3_symmetric::CryptographicHasher;
use sp1_primitives::poseidon2_hash;
use sp1_recursion_core::{
    air::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH},
    machine::RecursionAir,
};
use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, *};

/// The configuration for the core prover.
type F = BabyBear;
type SC = BabyBearPoseidon2;

const COMPRESS_DEGREE: usize = 3;

// TODO(tqn) static/const assertions for all these constants?

const RECURSION_VK_ROOT_U32: [u32; 8] =
    [779620665, 657361014, 1275916220, 1016544356, 761269804, 102002516, 650304731, 1117171342];

// TODO(tqn) assert these are ordered and (elsewhere) a subset of the allowed vkeys
const RECURSION_VK_SET_U32: [[u32; 8]; 10] = [
    [34634639, 1077419460, 522716272, 128546022, 1650539826, 972283970, 1473949484, 380704775],
    [85706223, 1525684246, 1199856741, 1391101846, 1792912762, 295614271, 314490649, 1502018005],
    [356142876, 1489851626, 1124548079, 831410721, 766841921, 873142415, 1391251580, 877773505],
    [425872273, 1461415488, 1244588344, 1060312257, 136306608, 1433707042, 1160776222, 524174492],
    [644696378, 418018153, 1226441221, 255714996, 1786747034, 1510857876, 297601848, 1123969544],
    [1025127812, 1127909068, 2003193535, 46492488, 1931961898, 127602006, 1372677902, 215288608],
    [1040739925, 47152779, 1977995560, 1837254256, 1802612327, 901764869, 164811616, 522489358],
    [1240986941, 319688287, 1532637695, 1295947740, 172448572, 77539038, 1604859325, 1247648270],
    [1765892442, 1982418848, 1908858230, 1759206396, 617909919, 135099116, 1978826499, 195368607],
    [1838947180, 300263103, 1583019599, 569344441, 1628950152, 1571784765, 194872493, 1215388499]
];

/// TODO(tqn) determine if we want to keep some state/cached data between calls.
/// Verify a compressed proof.
pub fn verify_compressed(
    proof: &SP1ReduceProof<SC>,
    vkey_hash: &[BabyBear; 8],
) -> Result<(), MachineVerificationError<SC>> {
    let SP1ReduceProof { vk: compress_vk, proof } = proof;

    let compress_machine: StarkMachine<SC, _> =
        RecursionAir::<F, COMPRESS_DEGREE>::compress_machine(SC::default());

    let mut challenger = compress_machine.config().challenger();
    let machine_proof = MachineProof { shard_proofs: vec![proof.clone()] };
    compress_machine.verify(compress_vk, &machine_proof, &mut challenger)?;

    // Validate public values
    let public_values: &RecursionPublicValues<_> = proof.public_values.as_slice().borrow();

    if !is_recursion_public_values_valid(compress_machine.config(), public_values) {
        return Err(MachineVerificationError::InvalidPublicValues(
            "recursion public values are invalid",
        ));
    }

    if public_values.vk_root != RECURSION_VK_ROOT_U32.map(BabyBear::from_canonical_u32) {
        return Err(MachineVerificationError::InvalidPublicValues("vk_root mismatch"));
    }

    let compress_vk_hash = hash_babybear(compress_vk).map(|x| x.as_canonical_u32());
    if RECURSION_VK_SET_U32.binary_search(&compress_vk_hash).is_err() {
        return Err(MachineVerificationError::InvalidVerificationKey);
    }

    // `is_complete` should be 1. In the reduce program, this ensures that the proof is fully
    // reduced.
    if public_values.is_complete != BabyBear::one() {
        return Err(MachineVerificationError::InvalidPublicValues("is_complete is not 1"));
    }

    // Verify that the proof is for the sp1 vkey we are expecting.
    if public_values.sp1_vk_digest != *vkey_hash {
        return Err(MachineVerificationError::InvalidPublicValues("sp1 vk hash mismatch"));
    }

    Ok(())
}

/// Compute the digest of the public values.
fn recursion_public_values_digest(
    config: &SC,
    public_values: &RecursionPublicValues<BabyBear>,
) -> [BabyBear; 8] {
    let hash = InnerHash::new(config.perm.clone());
    let pv_array = public_values.as_array();
    hash.hash_slice(&pv_array[0..NUM_PV_ELMS_TO_HASH])
}

/// Check if the digest of the public values is correct.
fn is_recursion_public_values_valid(
    config: &SC,
    public_values: &RecursionPublicValues<BabyBear>,
) -> bool {
    let expected_digest = recursion_public_values_digest(config, public_values);
    public_values.digest.iter().copied().eq(expected_digest)
}

fn hash_babybear(this: &StarkVerifyingKey<BabyBearPoseidon2>) -> [BabyBear; DIGEST_SIZE] {
    let mut num_inputs = DIGEST_SIZE + 1 + 14 + (7 * this.chip_information.len());
    for (name, _, _) in this.chip_information.iter() {
        num_inputs += name.len();
    }
    let mut inputs = Vec::with_capacity(num_inputs);
    inputs.extend(this.commit.as_ref());
    inputs.push(this.pc_start);
    inputs.extend(this.initial_global_cumulative_sum.0.x.0);
    inputs.extend(this.initial_global_cumulative_sum.0.y.0);
    for (name, domain, dimension) in this.chip_information.iter() {
        inputs.push(BabyBear::from_canonical_usize(domain.log_n));
        let size = 1 << domain.log_n;
        inputs.push(BabyBear::from_canonical_usize(size));
        let g = BabyBear::two_adic_generator(domain.log_n);
        inputs.push(domain.shift);
        inputs.push(g);
        inputs.push(BabyBear::from_canonical_usize(dimension.width));
        inputs.push(BabyBear::from_canonical_usize(dimension.height));
        inputs.push(BabyBear::from_canonical_usize(name.len()));
        for byte in name.as_bytes() {
            inputs.push(BabyBear::from_canonical_u8(*byte));
        }
    }

    poseidon2_hash(inputs)
}

/// A verifier for Groth16 zero-knowledge proofs.
#[derive(Debug)]
pub struct CompressedVerifier;
impl CompressedVerifier {
    pub fn verify(
        proof: &[u8],
        sp1_public_inputs: &[u8],
        sp1_vkey_hash: &[u8],
    ) -> Result<(), CompressedError> {
        let reduce_proof: SP1ReduceProof<SC> =
            bincode::deserialize(proof).map_err(CompressedError::Deserialization)?;

        let vkey_hash: [F; 8] =
            bincode::deserialize(sp1_vkey_hash).map_err(CompressedError::Deserialization)?;

        verify_compressed(&reduce_proof, &vkey_hash).map_err(CompressedError::Verification)?;

        Ok(())
    }
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CompressedError {
    // TODO(tqn) better errosr
    // #[error("Proof verification failed")]
    // ProofVerificationFailed,
    // #[error("Process verifying key failed")]
    // ProcessVerifyingKeyFailed,
    // #[error("Prepare inputs failed")]
    // PrepareInputsFailed,
    #[error("General error")]
    GeneralError(#[from] crate::error::Error),
    #[error("Deserialization error")]
    Deserialization(#[from] Box<bincode::ErrorKind>),
    #[error("Verification error")]
    Verification(#[from] MachineVerificationError<SC>),
}

pub fn square(x: u32) -> u32 {
    use p3_baby_bear::BabyBear;
    use p3_field::{AbstractField, PrimeField32};

    BabyBear::from_wrapped_u32(x).square().as_canonical_u32()
}
