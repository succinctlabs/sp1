use std::iter::repeat_with;

use slop_merkle_tree::{MerkleTreeTcs, MerkleTreeTcsError};
use slop_tensor::Tensor;
use thiserror::Error;

use crate::zk::dot_product::{
    dot_product, verify_zk_dot_product_pre_reveal, verify_zk_dot_product_reveal,
    MerkleOpeningProof, ZkDotProductError,
};
use crate::zk::error_correcting_code::{MultiplicativeCode, ZkCode};
use slop_algebra::{AbstractExtensionField, AbstractField, TwoAdicField};
use slop_challenger::{CanObserve, CanSampleBits, FieldChallenger, IopCtx};

use super::ZkHadamardTotalProof;
use super::{ZkHadamardAndDotsTotalProof, ZkHadamardProductProof, EVAL_SCHEDULE};

#[derive(Debug, Clone, Error)]
pub enum ZkHadamardProductError {
    #[error("inconsistent evaluations shape for commitment {0}")]
    InconsistentProofShape(String, Vec<usize>),
    #[error("u · D(phi)[0..n] does not equal rho_times * gamma")]
    FDotZInconsistency,
    #[error("inconsistent revealed evaluation at index {0}")]
    RevealedEvalInconsistency(usize),
    #[error("inconsistent hash commitment for {0}")]
    HashInconsistency(String, MerkleTreeTcsError),
}

#[derive(Debug, Clone, Error)]
pub enum ZkHadamardAndDotsError {
    #[error("hadamard error: {0}")]
    Hadamard(#[from] ZkHadamardProductError),
    #[error("dot product error: {0}")]
    DotProduct(ZkDotProductError),
}

/// First phase of zero-knowledge Hadamard product verification.
///
/// Fiat-Shamir sequence: observe commitment -> sample z_base -> observe gamma -> sample rho_times -> observe phi.
///
/// Verifies u · D(phi)[0..n] = rho_times * gamma where:
/// - u = [1, z_base, z_base^2, ...]
/// - D = square_to_base (reduction from product code to base code)
/// - gamma = u · D(r'_×)[0..n]
/// - phi = (C*)^{-1}(Ca' · Cb' - Cc' + rho_times · C*r'_×)
pub(in crate::zk::hadamard_product) fn verify_zk_hadamard_product_pre_reveal<GC: IopCtx, Code>(
    commitment: &GC::Digest,
    proof: &ZkHadamardProductProof<GC, Code>,
    challenger: &mut GC::Challenger,
) -> Result<GC::EF, ZkHadamardProductError>
where
    GC::EF: TwoAdicField,
    Code: MultiplicativeCode<GC::EF> + ZkCode<GC::EF>,
{
    let parameters = &proof.parameters;
    let pml = parameters.padded_message_length;

    // Check shape of phi (intermediate form for product code)
    if proof.phi.len() != 2 * pml.next_power_of_two() {
        return Err(ZkHadamardProductError::InconsistentProofShape(
            "phi length".to_string(),
            vec![proof.phi.len(), 2 * pml.next_power_of_two()],
        ));
    }

    // Fiat-Shamir sequence (must match prover exactly)
    // Round 1: observe commitment, sample z_base
    challenger.observe(*commitment);
    let z_base: GC::EF = challenger.sample_ext_element();

    // Round 2: observe gamma, sample rho_times
    challenger.observe_ext_element(proof.gamma);
    let rho_times: GC::EF = challenger.sample_ext_element();

    // Round 3: observe phi
    challenger.observe_ext_element_slice(&proof.phi[..]);

    // Compute u vector (powers of z_base)
    let n = pml - parameters.total_padding;
    let u: Vec<GC::EF> = z_base.powers().take(n).collect();

    // Apply reduction function D to phi
    let phi_reduced = Code::square_to_base(&proof.phi, parameters.code_length, pml);

    // Verify: u · D(phi)[0..n] = rho_times * gamma
    let u_dot_phi = dot_product(&u, &phi_reduced[..n]);
    let expected = rho_times * proof.gamma;
    if u_dot_phi != expected {
        return Err(ZkHadamardProductError::FDotZInconsistency);
    }

    Ok(rho_times)
}

/// Second phase of zero-knowledge Hadamard product verification: verify revealed evaluations and merkle proofs.
///
/// Verifies that each revealed evaluation satisfies:
/// (C* phi)[idx] = a_hat * b_hat - c_hat + rho_times * r_times_hat
/// where a_hat, b_hat, c_hat, r_times_hat are extracted from the combined tensor columns.
pub(in crate::zk::hadamard_product) fn verify_zk_hadamard_product_reveal<GC: IopCtx, Code>(
    commitment: &GC::Digest,
    proof: &ZkHadamardProductProof<GC, Code>,
    revealed_data: &MerkleOpeningProof<GC>,
    rho_times: GC::EF,
    revealed_indices: &[usize],
) -> Result<(), ZkHadamardProductError>
where
    GC::EF: TwoAdicField,
    Code: MultiplicativeCode<GC::EF> + ZkCode<GC::EF>,
{
    let d = <GC::EF as AbstractExtensionField<GC::F>>::D;
    let parameters = &proof.parameters;
    let expected_revealed_evals_len = parameters.multi_evals(&EVAL_SCHEDULE);

    // Check that we have enough revealed indices
    if revealed_indices.len() < expected_revealed_evals_len {
        return Err(ZkHadamardProductError::InconsistentProofShape(
            "revealed_indices".to_string(),
            vec![revealed_indices.len(), expected_revealed_evals_len],
        ));
    }

    // Check shape of revealed evaluations tensor
    let dims = revealed_data.revealed_evals.sizes();
    let expected_width = 5 * d;
    if dims.len() != 2 || dims[1] != expected_width {
        return Err(ZkHadamardProductError::InconsistentProofShape(
            "revealed_evals".to_string(),
            dims.to_vec(),
        ));
    }

    // Check Merkle commitment correctness for the combined commitment
    let merkle_verifier: MerkleTreeTcs<GC> = MerkleTreeTcs::default();
    if let Err(e) = merkle_verifier.verify_tensor_openings(
        commitment,
        revealed_indices,
        &revealed_data.revealed_evals,
        expected_width,
        parameters.code_log_length,
        &revealed_data.merkle_paths,
    ) {
        return Err(ZkHadamardProductError::HashInconsistency("combined".to_string(), e));
    }

    // Compute the full codeword C* phi
    let phi_codeword =
        Code::encode_square(&proof.phi, parameters.code_length, parameters.padded_message_length);

    // The tensor has shape [num_indices, 5 * d]
    // Columns: [a (d elems), b (d elems), c (d elems), r_+ (d elems), r_× (d elems)]
    let row_width = 5 * d;
    let num_indices = revealed_data.revealed_evals.sizes()[0];
    let combined_slice = revealed_data.revealed_evals.as_slice();

    // Check revealed evaluations consistency
    for (i, &idx) in revealed_indices.iter().enumerate() {
        if i >= num_indices {
            break;
        }

        let row_start = i * row_width;

        let a_hat = GC::EF::from_base_slice(&combined_slice[row_start..row_start + d]);
        let b_hat = GC::EF::from_base_slice(&combined_slice[row_start + d..row_start + 2 * d]);
        let c_hat = GC::EF::from_base_slice(&combined_slice[row_start + 2 * d..row_start + 3 * d]);
        // r_+ at [3d..4d] is not used in the product check
        let r_times_hat =
            GC::EF::from_base_slice(&combined_slice[row_start + 4 * d..row_start + 5 * d]);

        let expected_phi_eval = a_hat * b_hat - c_hat + rho_times * r_times_hat;

        if phi_codeword[idx] != expected_phi_eval {
            return Err(ZkHadamardProductError::RevealedEvalInconsistency(i));
        }
    }

    Ok(())
}

/// Verifies a zero-knowledge Hadamard product proof.
///
/// This is a convenience wrapper that calls `verify_zk_hadamard_product_pre_reveal`, samples indices,
/// and then calls `verify_zk_hadamard_product_reveal`.
pub fn verify_zk_hadamard_product<GC: IopCtx, Code>(
    commitment: &GC::Digest,
    total_proof: &ZkHadamardTotalProof<GC, Code>,
    challenger: &mut GC::Challenger,
) -> Result<(), ZkHadamardProductError>
where
    GC::EF: TwoAdicField,
    Code: MultiplicativeCode<GC::EF> + ZkCode<GC::EF>,
{
    let proof = &total_proof.proof;
    let rho_times = verify_zk_hadamard_product_pre_reveal(commitment, proof, challenger)?;
    let revealed_indices = repeat_with(|| challenger.sample_bits(proof.parameters.code_log_length))
        .take(proof.parameters.multi_evals(&EVAL_SCHEDULE))
        .collect::<Vec<_>>();
    verify_zk_hadamard_product_reveal(
        commitment,
        proof,
        &total_proof.proximity_check_proof,
        rho_times,
        &revealed_indices,
    )
}

/// Combined verification for Hadamard product and a batched dot product with shared indices.
///
/// Verifies both the Hadamard product proof and a single batched dot product proof
/// (whose `claimed_dot_products` has 3 entries: one per committed vector).
///
/// The `revealed_data` contains the full revealed evaluations tensor (shape [evals(2), 5*d])
/// and Merkle paths for all indices. The dot product verifier extracts the relevant subset.
pub fn verify_zk_hadamard_and_dots<GC: IopCtx, Code>(
    commitment: &GC::Digest,
    dot_vec: &[GC::EF],
    total_proof: &ZkHadamardAndDotsTotalProof<GC, Code>,
    challenger: &mut GC::Challenger,
) -> Result<(), ZkHadamardAndDotsError>
where
    GC::EF: TwoAdicField,
    Code: MultiplicativeCode<GC::EF> + ZkCode<GC::EF>,
{
    let hadamard_proof = &total_proof.hadamard_proof;
    let dot_proof = &total_proof.dot_proof;
    let revealed_data = &total_proof.proximity_check_proof;

    // Phase 1: All pre-reveals (before any index sampling)
    let rho_times = verify_zk_hadamard_product_pre_reveal(commitment, hadamard_proof, challenger)?;

    // Single dot product pre-reveal for the batched proof
    let rlc_coeff = verify_zk_dot_product_pre_reveal(commitment, dot_vec, dot_proof, challenger)
        .map_err(ZkHadamardAndDotsError::DotProduct)?;

    // Phase 2: Sample indices (single sampling point for all proofs)
    let revealed_indices =
        repeat_with(|| challenger.sample_bits(hadamard_proof.parameters.code_log_length))
            .take(hadamard_proof.parameters.multi_evals(&EVAL_SCHEDULE))
            .collect::<Vec<_>>();

    // Phase 3: Hadamard reveal with full 5*d-wide tensor (includes Merkle verification)
    verify_zk_hadamard_product_reveal(
        commitment,
        hadamard_proof,
        revealed_data,
        rho_times,
        &revealed_indices,
    )?;

    // Phase 4: Dot product reveal — extract first 4*d columns for the dot product subset
    let d = <GC::EF as AbstractExtensionField<GC::F>>::D;
    let abc_width = 4 * d;
    let total_width = revealed_data.revealed_evals.sizes()[1]; // 5*d
    let dot_evals = dot_proof.parameters.evals(1);
    let combined_slice = revealed_data.revealed_evals.as_slice();

    let mut extracted = Vec::with_capacity(dot_evals * abc_width);
    for i in 0..dot_evals {
        let row_start = i * total_width;
        extracted.extend_from_slice(&combined_slice[row_start..row_start + abc_width]);
    }
    let dot_revealed_evals = Tensor::from(extracted).reshape([dot_evals, abc_width]);

    let dot_indices = &revealed_indices[..dot_evals];
    verify_zk_dot_product_reveal(dot_proof, &dot_revealed_evals, rlc_coeff, dot_indices)
        .map_err(ZkHadamardAndDotsError::DotProduct)?;

    Ok(())
}
