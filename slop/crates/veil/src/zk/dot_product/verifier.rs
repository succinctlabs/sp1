use std::iter::repeat_with;

use crate::zk::error_correcting_code::ZkCode;
use slop_merkle_tree::{MerkleTreeTcs, MerkleTreeTcsError};
use slop_tensor::Tensor;
use thiserror::Error;

use slop_algebra::{AbstractExtensionField, AbstractField, TwoAdicField};
use slop_challenger::{CanObserve, CanSampleBits, FieldChallenger, IopCtx};

use super::{dot_product, ZkDotProductProof, ZkDotTotalProof};

#[derive(Debug, Clone, Error)]
pub enum ZkDotProductError {
    #[error("inconsistent evaluations shape: {1:?}")]
    InconsistentProofShape(Vec<usize>, String),
    #[error("inconsistent RLC dot product")]
    RLCDotInconsistency,
    #[error("inconsistent revealed evaluation")]
    RevealedEvalInconsistency(usize),
    #[error("inconsistent hash commitment")]
    HashInconsistency(MerkleTreeTcsError),
}

/// First phase of zero-knowledge batch dot product verification: observe messages and verify RLC consistency.
///
/// Checks that the claimed dot products (one per committed vector) are consistent with the
/// RLC vector via Horner evaluation. Performs shape checks, observes round 1 and round 2
/// messages on the challenger, and returns the RLC coefficient needed to complete verification.
#[doc(hidden)]
pub fn verify_zk_dot_product_pre_reveal<GC: IopCtx, Code: ZkCode<GC::EF>>(
    commitment: &GC::Digest,
    dot_vec: &[GC::EF],
    proof: &ZkDotProductProof<GC, Code>,
    challenger: &mut GC::Challenger,
) -> Result<GC::EF, ZkDotProductError> {
    let parameters = &proof.parameters;
    let length = dot_vec.len();

    // Check that dot_vec length matches the message length
    if length != proof.rlc_vec.len() {
        return Err(ZkDotProductError::InconsistentProofShape(
            vec![length, parameters.padded_message_length],
            "dot_vec length does not match rlc_vec length".to_string(),
        ));
    }
    // Check that code parameters match proof lengths
    if parameters.padded_message_length != proof.rlc_vec.len() + proof.rlc_padding.len() {
        return Err(ZkDotProductError::InconsistentProofShape(
            vec![proof.rlc_vec.len(), parameters.padded_message_length],
            "padded_message_length does not match rlc_vec + rlc_padding length".to_string(),
        ));
    }
    // Check that padding length is at least evals
    if proof.rlc_padding.len() < parameters.evals(1) {
        return Err(ZkDotProductError::InconsistentProofShape(
            vec![proof.rlc_padding.len(), parameters.evals(1)],
            "padding length must be at least evals".to_string(),
        ));
    }

    // Round 1: observe dot products and commitment, sample RLC coefficient
    challenger.observe_ext_element_slice(dot_vec);
    challenger.observe_ext_element_slice(&proof.claimed_dot_products);
    challenger.observe_ext_element(proof.mask_dot_product);
    challenger.observe(*commitment);
    let rho: GC::EF = challenger.sample_ext_element();

    // Check RLC dot product via Horner: sum(rho^j * dp_j) + rho^N * mask_dp
    let expected_rlc_dp = proof
        .claimed_dot_products
        .iter()
        .chain(std::iter::once(&proof.mask_dot_product))
        .rev()
        .copied()
        .fold(GC::EF::zero(), |acc, dp| dp + rho * acc);
    if expected_rlc_dp != dot_product(&proof.rlc_vec, dot_vec) {
        return Err(ZkDotProductError::RLCDotInconsistency);
    }

    // Round 2: observe RLC vectors
    challenger.observe_ext_element_slice(&proof.rlc_vec[..]);
    challenger.observe_ext_element_slice(&proof.rlc_padding[..]);

    Ok(rho)
}

/// Verify revealed evaluations without Merkle proof verification.
///
/// For each revealed index, recomputes the RLC of all column evaluations (one per committed
/// vector plus the mask) via Horner and checks it matches the FFT of the RLC vector.
///
/// Use this when the Merkle verification is handled externally (e.g., when using a shared
/// commitment with the Hadamard product proof).
///
/// # Arguments
/// * `proof` - The dot product proof containing RLC data and parameters
/// * `revealed_evals` - The revealed evaluation tensor (may be extracted from a larger combined tensor)
/// * `rlc_coeff` - The RLC coefficient from the pre-reveal phase
/// * `revealed_indices` - The indices at which evaluations were revealed
#[doc(hidden)]
pub fn verify_zk_dot_product_reveal<GC: IopCtx, Code: ZkCode<GC::EF>>(
    proof: &ZkDotProductProof<GC, Code>,
    revealed_evals: &Tensor<GC::F>,
    rlc_coeff: GC::EF,
    revealed_indices: &[usize],
) -> Result<(), ZkDotProductError>
where
    GC::EF: TwoAdicField,
{
    let parameters = &proof.parameters;

    // Shape check on revealed_evals
    let d = <GC::EF as AbstractExtensionField<GC::F>>::D;
    let num_input_vecs = proof.claimed_dot_products.len();
    let dims = revealed_evals.sizes();
    if dims.len() != 2 || dims[0] != parameters.evals(1) || dims[1] != (num_input_vecs + 1) * d {
        return Err(ZkDotProductError::InconsistentProofShape(
            dims.to_vec(),
            "revealed_evals shape does not match expected dimensions".to_string(),
        ));
    }

    // Evaluate the RLC polynomial directly at the revealed indices via Horner,
    // instead of computing a full FFT over the entire code domain.
    // O(num_evals * padded_message_length) vs O(code_length * log(code_length)).
    let coeffs = [&proof.rlc_vec[..], &proof.rlc_padding[..]].concat();
    let encoded_at_indices =
        Code::encode_at_indices(&coeffs, parameters.code_length, revealed_indices);

    // Check revealed evaluations via Horner over all columns.
    // Work directly on the base field slice to avoid an expensive Tensor clone + into_extension.
    let base_slice = revealed_evals.as_slice();
    let [_num_evals, base_width]: [usize; 2] = revealed_evals.sizes().try_into().unwrap();
    let ext_width = base_width / d;

    for (i, &expected) in encoded_at_indices.iter().enumerate() {
        let row_start = i * base_width;
        let rlc_eval = (0..ext_width).rev().fold(GC::EF::zero(), |acc, j| {
            let elem =
                GC::EF::from_base_slice(&base_slice[row_start + j * d..row_start + (j + 1) * d]);
            elem + rlc_coeff * acc
        });
        if rlc_eval != expected {
            return Err(ZkDotProductError::RevealedEvalInconsistency(i));
        }
    }

    Ok(())
}

/// Verifies a zero-knowledge dot product proof for a batch of committed vectors.
///
/// Runs the full verification pipeline: RLC consistency check, Merkle proof verification,
/// and revealed evaluation checks.
pub fn verify_zk_dot_product<GC: IopCtx, Code: ZkCode<GC::EF>>(
    commitment: &GC::Digest,
    dot_vec: &[GC::EF],
    total_proof: &ZkDotTotalProof<GC, Code>,
    challenger: &mut GC::Challenger,
) -> Result<(), ZkDotProductError>
where
    GC::EF: TwoAdicField,
{
    let proof = &total_proof.proof;
    let revealed_data = &total_proof.proximity_check_proof;

    let rlc_coeff = verify_zk_dot_product_pre_reveal(commitment, dot_vec, proof, challenger)?;
    let revealed_indices = repeat_with(|| challenger.sample_bits(proof.parameters.code_log_length))
        .take(proof.parameters.evals(1))
        .collect::<Vec<_>>();

    // Check Merkle commitment correctness
    let merkle_verifier: MerkleTreeTcs<GC> = MerkleTreeTcs::default();
    if let Err(e) = merkle_verifier.verify_tensor_openings(
        commitment,
        &revealed_indices,
        &revealed_data.revealed_evals,
        &revealed_data.merkle_paths,
    ) {
        return Err(ZkDotProductError::HashInconsistency(e));
    }

    verify_zk_dot_product_reveal(proof, &revealed_data.revealed_evals, rlc_coeff, &revealed_indices)
}

/// Verifies a dot product proof against multiple dot vectors using RLC.
///
/// Combines multiple `dot_vecs` into a single RLC vector, then delegates to
/// [`verify_zk_dot_product`]. This is the verifier counterpart to [`zk_dot_products_proof`].
pub fn verify_zk_dot_products<GC: IopCtx, Code: ZkCode<GC::EF>>(
    commitment: &GC::Digest,
    dot_vecs: &[Vec<GC::EF>],
    total_proof: &ZkDotTotalProof<GC, Code>,
    challenger: &mut GC::Challenger,
) -> Result<(), ZkDotProductError>
where
    GC::EF: TwoAdicField,
{
    let proof = &total_proof.proof;

    // Check that all dot_vecs have the same length as the proof's message length
    let expected_len = proof.rlc_vec.len();
    if dot_vecs.is_empty() {
        return Err(ZkDotProductError::InconsistentProofShape(
            vec![0, expected_len],
            "dot_vecs is empty".to_string(),
        ));
    }
    if !dot_vecs.iter().all(|v| v.len() == expected_len) {
        return Err(ZkDotProductError::InconsistentProofShape(
            dot_vecs.iter().map(|v| v.len()).collect(),
            "not all dot_vecs have the expected length".to_string(),
        ));
    }

    // Sample RLC coefficient
    let rlc_coeff: GC::EF = challenger.sample_ext_element();

    // Compute RLC of dot_vecs (same as in prover)
    let (rlc_vec, _) = dot_vecs.iter().skip(1).fold(
        (dot_vecs[0].clone(), GC::EF::one()),
        |(acc_vec, factor), next_vec| {
            let new_factor = factor * rlc_coeff;
            let new_vec =
                acc_vec.iter().zip(next_vec.iter()).map(|(a, b)| *a + new_factor * *b).collect();
            (new_vec, new_factor)
        },
    );

    // Verify using the split pre_reveal/reveal pipeline with RLC'd dot_vec
    let rlc_coeff2 = verify_zk_dot_product_pre_reveal(commitment, &rlc_vec, proof, challenger)?;
    let revealed_indices = repeat_with(|| challenger.sample_bits(proof.parameters.code_log_length))
        .take(proof.parameters.evals(1))
        .collect::<Vec<_>>();

    let merkle_verifier: MerkleTreeTcs<GC> = MerkleTreeTcs::default();
    if let Err(e) = merkle_verifier.verify_tensor_openings(
        commitment,
        &revealed_indices,
        &total_proof.proximity_check_proof.revealed_evals,
        &total_proof.proximity_check_proof.merkle_paths,
    ) {
        return Err(ZkDotProductError::HashInconsistency(e));
    }

    verify_zk_dot_product_reveal(
        proof,
        &total_proof.proximity_check_proof.revealed_evals,
        rlc_coeff2,
        &revealed_indices,
    )
}
