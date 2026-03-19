use crate::zk::error_correcting_code::{CodeParametersForZk, ZkCode};
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use slop_algebra::AbstractField;
use slop_alloc::CpuBackend;
use slop_challenger::{CanObserve, CanSampleBits, FieldChallenger, IopCtx};
use slop_commit::Message;
use slop_matrix::dense::RowMajorMatrix;
use slop_merkle_tree::{ComputeTcsOpenings, MerkleTreeTcsProof, TensorCsProver};
use slop_tensor::Tensor;

use std::iter::repeat_with;

// Setup constants---choose for target bits of security
pub(in crate::zk::dot_product) const CODE_INVERSE_RATE: f64 = 16.0;
pub(in crate::zk::dot_product) const SECURITY_BITS: usize = 100;

// ============================================================================
// FINAL PROOF OUTPUT
// ============================================================================

/// Merkle tree openings shared between proofs.
///
/// Contains the revealed evaluations tensor and Merkle authentication paths.
/// In combined proof scenarios (e.g., Hadamard + dot product), a single
/// `MerkleOpeningProof` is shared to avoid redundancy.
#[doc(hidden)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MerkleOpeningProof<GC: IopCtx> {
    pub revealed_evals: Tensor<GC::F>,
    pub merkle_paths: MerkleTreeTcsProof<GC::Digest>,
}

/// A proof that a batch of committed vectors has claimed dot products with a given test vector.
///
/// Contains the algebraic proof data (dot products, RLC vectors) but NOT the revealed
/// evaluations or Merkle paths — those are in [`MerkleOpeningProof`].
#[doc(hidden)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct ZkDotProductProof<GC: IopCtx, Code: ZkCode<GC::EF>> {
    pub claimed_dot_products: Vec<GC::EF>,
    pub mask_dot_product: GC::EF,
    pub rlc_vec: Vec<GC::EF>,
    pub rlc_padding: Vec<GC::EF>,
    pub parameters: CodeParametersForZk<GC::EF, Code>,
}

/// Complete dot product proof: algebraic proof data + Merkle openings.
///
/// This is the output of [`zk_dot_product_proof`] and input to [`verify_zk_dot_product`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct ZkDotTotalProof<GC: IopCtx, Code: ZkCode<GC::EF>> {
    pub(in crate::zk::dot_product) proof: ZkDotProductProof<GC, Code>,
    pub(in crate::zk::dot_product) proximity_check_proof: MerkleOpeningProof<GC>,
}

impl<GC: IopCtx, Code: ZkCode<GC::EF>> ZkDotTotalProof<GC, Code> {
    /// Returns the claimed dot products (one per committed vector).
    pub fn claimed_dot_products(&self) -> &[GC::EF] {
        &self.proof.claimed_dot_products
    }
}

// ============================================================================
// COMMITMENT PHASE: Encode vectors and build Merkle trees
// ============================================================================

/// Prover data for a batch of committed vectors pre-Merkleization.
///
/// Output of [`zk_vector_encode`]. Contains the original vectors, random
/// masking data, and code parameters needed for zero-knowledge proof generation.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct ZkVectorPreProverData<GC: IopCtx, Code: ZkCode<GC::EF>> {
    pub in_vecs: Vec<Vec<GC::EF>>,
    pub masks: Vec<GC::EF>,
    pub padding: Vec<GC::EF>,
    pub parameters: CodeParametersForZk<GC::EF, Code>,
}

/// Encodes a batch of vectors for commitment without building the Merkle tree.
///
/// Each call encodes one or more input vectors together with a shared random mask into a single
/// FFT-encoded tensor of width `in_vecs.len() + 1`. This is useful when multiple encoded batches
/// will share a single Merkle tree commitment.
///
/// Use [`zk_vectors_merkleize`] to build the Merkle tree from encoded batches.
#[doc(hidden)]
pub fn zk_vector_encode<GC: IopCtx, RNG: CryptoRng + Rng, Code: ZkCode<GC::EF>>(
    in_vecs: &[Vec<GC::EF>],
    rng: &mut RNG,
    padding_schedule: &[usize],
) -> (Tensor<GC::F>, ZkVectorPreProverData<GC, Code>)
where
    rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
{
    assert!(!in_vecs.is_empty(), "Must provide at least one input vector");
    let length = in_vecs[0].len();
    assert!(in_vecs.iter().all(|v| v.len() == length), "All input vectors must have same length");
    let width = in_vecs.len() + 1;

    let parameters =
        CodeParametersForZk::new(length, SECURITY_BITS, CODE_INVERSE_RATE, padding_schedule);

    // Generate masking vector
    let masks: Vec<GC::EF> = repeat_with(|| rng.gen()).take(length).collect();

    // Generate padding columns
    let padding: Vec<GC::EF> =
        repeat_with(|| rng.gen()).take(width * parameters.total_padding).collect();

    // Compute FFT encoding: each row is [in_vecs[0][i], ..., in_vecs[N-1][i], masks[i]]
    let code_input_vec: Vec<GC::EF> = (0..length)
        .flat_map(|i| in_vecs.iter().map(move |v| v[i]).chain(std::iter::once(masks[i])))
        .chain(padding.iter().copied())
        .collect();
    let code_input = RowMajorMatrix::new(code_input_vec, width);
    let code_output = Code::batch_encode(code_input, parameters.code_length);
    let to_merkleize: Tensor<GC::F, CpuBackend> = code_output.flatten_to_base().into();

    let prover_data =
        ZkVectorPreProverData { in_vecs: in_vecs.to_vec(), masks, padding, parameters };

    (to_merkleize, prover_data)
}

/// Committed batch data needed for proof generation.
///
/// Output of [`zk_vector_merkleize`] or [`zk_vector_commit`].
/// Contains everything needed to generate dot product proofs for a batch of vectors.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct ZkVectorProverData<GC: IopCtx, ProverData, Code: ZkCode<GC::EF>> {
    pub merkle_tree: ProverData,
    pub in_vecs: Vec<Vec<GC::EF>>,
    pub padding: Vec<GC::EF>,
    pub masks: Vec<GC::EF>,
    pub to_merkleize_message: Message<Tensor<GC::F>>,
    pub parameters: CodeParametersForZk<GC::EF, Code>,
}

/// Builds a Merkle tree from an encoded vector batch.
///
/// Takes pre-merkle encoded data and builds a Merkle tree.
/// Returns the commitment digest and commitment data.
///
/// Use [`zk_vector_encode`] to prepare the vector batch for this function.
#[allow(clippy::type_complexity)]
pub(in crate::zk::dot_product) fn zk_vector_merkleize<
    GC: IopCtx,
    MK: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
    Code: ZkCode<GC::EF>,
>(
    to_merkleize: Tensor<GC::F>,
    secrets: ZkVectorPreProverData<GC, Code>,
    merkleizer: &MK,
) -> (GC::Digest, ZkVectorProverData<GC, MK::ProverData, Code>) {
    let to_merkleize_message: Message<Tensor<GC::F>> = vec![to_merkleize].into();

    // Build Merkle tree
    let (commitment, merkle_tree) =
        merkleizer.commit_tensors(to_merkleize_message.clone()).unwrap();

    let commitment_data = ZkVectorProverData {
        merkle_tree,
        in_vecs: secrets.in_vecs,
        padding: secrets.padding,
        masks: secrets.masks,
        to_merkleize_message,
        parameters: secrets.parameters,
    };

    (commitment, commitment_data)
}

/// Commits to a batch of vectors with a custom padding schedule (encode + merkleize in one step).
///
/// Returns the commitment and data needed for proof generation.
pub(in crate::zk::dot_product) fn zk_vector_commit<
    GC: IopCtx,
    MK: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
    RNG: CryptoRng + Rng,
    Code: ZkCode<GC::EF>,
>(
    in_vecs: &[Vec<GC::EF>],
    rng: &mut RNG,
    merkleizer: &MK,
    padding_schedule: &[usize],
) -> (GC::Digest, ZkVectorProverData<GC, MK::ProverData, Code>)
where
    rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
{
    let (to_merkleize, pre_prover_data) =
        zk_vector_encode::<GC, RNG, Code>(in_vecs, rng, padding_schedule);
    zk_vector_merkleize::<GC, MK, Code>(to_merkleize, pre_prover_data, merkleizer)
}

/// Commits to a batch of vectors for zero-knowledge dot product (uses default padding schedule).
///
/// Convenience wrapper for [`zk_vector_commit`] with padding schedule `&[1]`.
pub fn zk_dot_product_commitment<
    GC: IopCtx,
    MK: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
    RNG: CryptoRng + Rng,
    Code: ZkCode<GC::EF>,
>(
    in_vecs: &[Vec<GC::EF>],
    rng: &mut RNG,
    merkleizer: &MK,
) -> (GC::Digest, ZkVectorProverData<GC, MK::ProverData, Code>)
where
    rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
{
    zk_vector_commit(in_vecs, rng, merkleizer, &[1])
}

// ============================================================================
// PROOF GENERATION PHASE: Compute dot products and reveal evaluations
// ============================================================================

/// Intermediate state after computing dot products and RLC, before revealing evaluations.
///
/// Output of [`zk_dot_product_pre_reveal`]. Use with revealed indices to build the final proof.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct ZkDotProductPreReveal<GC: IopCtx, ProverData, Code: ZkCode<GC::EF>> {
    pub claimed_dot_products: Vec<GC::EF>,
    pub mask_dot_product: GC::EF,
    pub rlc_vec: Vec<GC::EF>,
    pub rlc_padding: Vec<GC::EF>,
    pub merkle_tree: ProverData,
    pub to_merkleize_message: Message<Tensor<GC::F>>,
    pub parameters: CodeParametersForZk<GC::EF, Code>,
}

/// First phase of proof generation: compute dot products and RLC for a batch.
///
/// Computes the dot product of each committed vector with `dot_vec`, then combines
/// all vectors and the mask via Horner RLC. Observes messages on the challenger and
/// returns intermediate state. Call [`zk_dot_product_reveal`] to complete the proof.
#[doc(hidden)]
pub fn zk_dot_product_pre_reveal<GC: IopCtx, ProverData, Code: ZkCode<GC::EF>>(
    dot_vec: &[GC::EF],
    commitment: &GC::Digest,
    commitment_data: ZkVectorProverData<GC, ProverData, Code>,
    challenger: &mut GC::Challenger,
) -> ZkDotProductPreReveal<GC, ProverData, Code> {
    let ZkVectorProverData {
        merkle_tree,
        in_vecs,
        padding,
        masks,
        to_merkleize_message,
        parameters,
        ..
    } = commitment_data;

    let width = in_vecs.len() + 1;
    let length = in_vecs[0].len();
    assert_eq!(dot_vec.len(), length, "dot_vec length must match in_vec length");
    assert!(
        padding.len() >= width * parameters.total_padding,
        "padding length must be at least width * total_padding"
    );

    // Compute dot products for all input vectors and the mask
    let claimed_dot_products: Vec<GC::EF> =
        in_vecs.iter().map(|v| dot_product(v, dot_vec)).collect();
    let mask_dot_product = dot_product(&masks, dot_vec);

    // Observe first round messages and draw randomness
    challenger.observe_ext_element_slice(dot_vec);
    challenger.observe_ext_element_slice(&claimed_dot_products);
    challenger.observe_ext_element(mask_dot_product);
    challenger.observe(*commitment);
    let rho: GC::EF = challenger.sample_ext_element();

    // Compute RLC via Horner: rlc[i] = in_vecs[0][i] + rho*(in_vecs[1][i] + ... + rho*masks[i])
    let rlc_vec: Vec<GC::EF> = (0..length)
        .map(|i| in_vecs.iter().rev().fold(masks[i], |acc, v| v[i] + rho * acc))
        .collect();
    let rlc_padding: Vec<GC::EF> = padding
        .chunks(width)
        .map(|row| row.iter().rev().copied().fold(GC::EF::zero(), |acc, x| x + rho * acc))
        .collect();

    // Observe second round messages
    challenger.observe_ext_element_slice(&rlc_vec[..]);
    challenger.observe_ext_element_slice(&rlc_padding[..]);

    ZkDotProductPreReveal {
        claimed_dot_products,
        mask_dot_product,
        rlc_vec,
        rlc_padding,
        merkle_tree,
        to_merkleize_message,
        parameters,
    }
}

/// Generates a complete zero-knowledge dot product proof for a batch of vectors.
///
/// Proves that each committed vector has the claimed dot product with `dot_vec`.
/// Handles the complete proof generation including Merkle openings.
/// For shared Merkle tree scenarios (e.g., Hadamard+dots), use [`zk_dot_product_pre_reveal`]
/// and build the proof manually with extracted columns.
pub fn zk_dot_product_proof<
    GC: IopCtx,
    MK: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
    Code: ZkCode<GC::EF>,
>(
    dot_vec: &[GC::EF],
    commitment: &GC::Digest,
    commitment_data: ZkVectorProverData<GC, MK::ProverData, Code>,
    challenger: &mut GC::Challenger,
    merkleizer: &MK,
) -> ZkDotTotalProof<GC, Code> {
    let pre_reveal = zk_dot_product_pre_reveal(dot_vec, commitment, commitment_data, challenger);

    // Sample revealed indices
    let revealed_indices =
        repeat_with(|| challenger.sample_bits(pre_reveal.parameters.code_log_length))
            .take(pre_reveal.parameters.evals(1))
            .collect::<Vec<_>>();

    // Compute Merkle openings directly
    let revealed_evals =
        merkleizer.compute_openings_at_indices(pre_reveal.to_merkleize_message, &revealed_indices);
    let merkle_paths =
        merkleizer.prove_openings_at_indices(pre_reveal.merkle_tree, &revealed_indices).unwrap();

    let proof = ZkDotProductProof {
        claimed_dot_products: pre_reveal.claimed_dot_products,
        mask_dot_product: pre_reveal.mask_dot_product,
        rlc_vec: pre_reveal.rlc_vec,
        rlc_padding: pre_reveal.rlc_padding,
        parameters: pre_reveal.parameters,
    };
    let revealed_data = MerkleOpeningProof { revealed_evals, merkle_paths };

    ZkDotTotalProof { proof, proximity_check_proof: revealed_data }
}

/// Generates a proof for multiple dot vectors against a batch of committed vectors using RLC.
///
/// Combines multiple `dot_vecs` into a single RLC vector, then delegates to
/// [`zk_dot_product_proof`]. All `dot_vecs` must have the same length as the committed vectors.
pub fn zk_dot_products_proof<
    GC: IopCtx,
    MK: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
    Code: ZkCode<GC::EF>,
>(
    dot_vecs: &[Vec<GC::EF>],
    commitment: GC::Digest,
    commitment_data: ZkVectorProverData<GC, MK::ProverData, Code>,
    challenger: &mut GC::Challenger,
    merkleizer: &MK,
) -> ZkDotTotalProof<GC, Code> {
    assert!(!dot_vecs.is_empty(), "dot_vecs cannot be empty");
    let expected_len = commitment_data.in_vecs[0].len();
    assert!(
        dot_vecs.iter().all(|v| v.len() == expected_len),
        "All dot_vecs must have the same length as the committed vectors"
    );

    let rlc_coeff: GC::EF = challenger.sample_ext_element();

    let (rlc_vec, _) = dot_vecs.iter().skip(1).fold(
        (dot_vecs[0].clone(), GC::EF::one()),
        |(acc_vec, factor), next_vec| {
            let new_factor = factor * rlc_coeff;
            let new_vec =
                acc_vec.iter().zip(next_vec.iter()).map(|(a, b)| *a + new_factor * *b).collect();
            (new_vec, new_factor)
        },
    );

    zk_dot_product_proof::<GC, MK, Code>(
        &rlc_vec,
        &commitment,
        commitment_data,
        challenger,
        merkleizer,
    )
}

// ============================================================================
// UTILITIES
// ============================================================================

/// Computes the dot product of two vectors.
pub fn dot_product<K>(in_vec: &[K], dot_vec: &[K]) -> K
where
    K: AbstractField + Copy,
{
    in_vec.iter().zip_eq(dot_vec.iter()).map(|(a, b)| *a * *b).sum()
}
