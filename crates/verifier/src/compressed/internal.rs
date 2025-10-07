//! Internal constants and types that determine the verifier configuration.
//!
//! # Warning
//! The contents of this module may change between minor versions.

use alloc::{vec, vec::Vec};
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

use super::CompressedError;
use crate::{blake3_hash, hash_public_inputs, hash_public_inputs_with_fn};

// NOTE: that all these constants and types are checked by sp1_prover::tests::sp1_verifier_valid.
// If you add a new proof, you MUST add to the test in that crate.
//
// Instructions to obtain `RECURSION_VK_SET` (and `RECURSION_VK_ROOT`) can be found in the test.

/// The finite field used for compress proofs.
pub type F = BabyBear;
/// The stark configuration used for compress proofs.
pub type SC = BabyBearPoseidon2;

/// Degree of Poseidon2 etc. in the compress machine.
pub const COMPRESS_DEGREE: usize = 3;

/// The vkey merkle tree root's digest. Fixed between SP1 major versions.
pub const RECURSION_VK_ROOT: [u32; 8] =
    [779620665, 657361014, 1275916220, 1016544356, 761269804, 102002516, 650304731, 1117171342];

/// A sorted list of digests for allowed vkeys in the vkey set/merkle tree. This is a subset of
/// the true collection of vkey digests, which is megabytes in size. These keys are precisely
/// the ones necessary to verify multi-shard proofs.
pub const RECURSION_VK_SET: &[[u32; 8]] = &[
    [34634639, 1077419460, 522716272, 128546022, 1650539826, 972283970, 1473949484, 380704775],
    [85706223, 1525684246, 1199856741, 1391101846, 1792912762, 295614271, 314490649, 1502018005],
    [356142876, 1489851626, 1124548079, 831410721, 766841921, 873142415, 1391251580, 877773505],
    [425872273, 1461415488, 1244588344, 1060312257, 136306608, 1433707042, 1160776222, 524174492],
    [644696378, 418018153, 1226441221, 255714996, 1786747034, 1510857876, 297601848, 1123969544],
    [1025127812, 1127909068, 2003193535, 46492488, 1931961898, 127602006, 1372677902, 215288608],
    [1040739925, 47152779, 1977995560, 1837254256, 1802612327, 901764869, 164811616, 522489358],
    [1240986941, 319688287, 1532637695, 1295947740, 172448572, 77539038, 1604859325, 1247648270],
    [1765892442, 1982418848, 1908858230, 1759206396, 617909919, 135099116, 1978826499, 195368607],
    [1838947180, 300263103, 1583019599, 569344441, 1628950152, 1571784765, 194872493, 1215388499],
];

/// Unwraps `sp1_proof: &SP1Proof` into a `&SP1ReduceProof<SC>`, returning
/// `Err(CompressedError::Mode(...))` if the variant is not [`SP1Proof::Compressed`].
/// Then, calls [`verify_sp1_reduce_proof`] and returns the result.
pub fn verify_sp1_proof(
    sp1_proof: &SP1Proof,
    sp1_public_inputs: &[u8],
    vkey_hash: &[BabyBear; 8],
) -> Result<(), CompressedError> {
    let SP1Proof::Compressed(reduce_proof) = sp1_proof else {
        return Err(CompressedError::Mode(sp1_proof.into()));
    };
    verify_sp1_reduce_proof(reduce_proof.as_ref(), sp1_public_inputs, vkey_hash)
}

// The rest of the functions in this file have been copied from elsewhere with slight modifications.

/// Verify a compressed proof.
pub fn verify_sp1_reduce_proof(
    reduce_proof: &SP1ReduceProof<SC>,
    sp1_public_inputs: &[u8],
    vkey_hash: &[BabyBear; 8],
) -> Result<(), CompressedError> {
    let SP1ReduceProof { vk: compress_vk, proof } = reduce_proof;

    let public_values: &RecursionPublicValues<_> = proof.public_values.as_slice().borrow();
    // This verifier does not support single-shard proofs because of the hard-coded vkey set.
    if public_values.next_shard == public_values.start_shard + F::one() {
        return Err(CompressedError::SingleShard);
    }

    let compress_machine: StarkMachine<SC, _> =
        RecursionAir::<F, COMPRESS_DEGREE>::compress_machine(SC::default());

    let mut challenger = compress_machine.config().challenger();
    let machine_proof = MachineProof { shard_proofs: vec![proof.clone()] };
    compress_machine.verify(compress_vk, &machine_proof, &mut challenger)?;

    // Validate the SP1 public values against the committed digest.
    let committed_value_digest_bytes = public_values
        .committed_value_digest
        .iter()
        .flat_map(|w| w.0.iter().map(|x| x.as_canonical_u32() as u8))
        .collect::<Vec<_>>();

    if committed_value_digest_bytes.as_slice() != hash_public_inputs(sp1_public_inputs).as_slice() &&
        committed_value_digest_bytes.as_slice() !=
            hash_public_inputs_with_fn(sp1_public_inputs, blake3_hash)
    {
        return Err(CompressedError::PublicValuesMismatch);
    }

    // Validate recursion's public values.
    if !is_recursion_public_values_valid(compress_machine.config(), public_values) {
        return Err(MachineVerificationError::InvalidPublicValues(
            "recursion public values are invalid",
        )
        .into());
    }

    if public_values.vk_root != RECURSION_VK_ROOT.map(BabyBear::from_canonical_u32) {
        return Err(MachineVerificationError::InvalidPublicValues("vk_root mismatch").into());
    }

    let compress_vk_hash = hash_babybear(compress_vk).map(|x| x.as_canonical_u32());
    if RECURSION_VK_SET.binary_search(&compress_vk_hash).is_err() {
        return Err(MachineVerificationError::InvalidVerificationKey.into());
    }

    // `is_complete` should be 1. In the reduce program, this ensures that the proof is fully
    // reduced.
    if public_values.is_complete != BabyBear::one() {
        return Err(MachineVerificationError::InvalidPublicValues("is_complete is not 1").into());
    }

    // Verify that the proof is for the sp1 vkey we are expecting.
    if public_values.sp1_vk_digest != *vkey_hash {
        return Err(MachineVerificationError::InvalidPublicValues("sp1 vk hash mismatch").into());
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
