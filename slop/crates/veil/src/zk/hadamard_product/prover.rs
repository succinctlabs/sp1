use crate::zk::dot_product::{
    dot_product, zk_dot_product_pre_reveal, zk_vector_encode, MerkleOpeningProof,
    ZkDotProductPreReveal, ZkDotProductProof, ZkVectorProverData,
};
use crate::zk::error_correcting_code::{CodeParametersForZk, MultiplicativeCode, ZkCode};
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractField, TwoAdicField};
use slop_alloc::CpuBackend;
use slop_challenger::{CanObserve, CanSampleBits, FieldChallenger, IopCtx};
use slop_commit::Message;
use slop_matrix::dense::RowMajorMatrix;
use slop_merkle_tree::{ComputeTcsOpenings, TensorCsProver};
use slop_tensor::Tensor;

use std::iter::repeat_with;

// Setup constants---choose for target bits of security
pub(in crate::zk::hadamard_product) const EVAL_SCHEDULE: [usize; 1] = [2];

/// A proof that three vectors satisfy the Hadamard product relationship: `a_i * b_i = c_i` for all `i`.
///
/// Uses two masks: an additive mask r_+ (shared with [a, b, c] in a single batch encoding)
/// and a multiplicative mask r_× (encoded with the product code C*).
///
/// The revealed evaluations and Merkle paths are in [`MerkleOpeningProof`], not in this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub(in crate::zk::hadamard_product) struct ZkHadamardProductProof<GC: IopCtx, Code>
where
    Code: MultiplicativeCode<GC::EF> + ZkCode<GC::EF>,
{
    /// gamma = u · D(r'_×)[0..n], where u = powers of z_base
    pub(in crate::zk::hadamard_product) gamma: GC::EF,
    /// phi = (C*)^{-1}(Ca' · Cb' - Cc' + rho_times · C*r'_×)
    pub(in crate::zk::hadamard_product) phi: Vec<GC::EF>,
    pub(in crate::zk::hadamard_product) parameters: CodeParametersForZk<GC::EF, Code>,
}

/// Complete Hadamard product proof: algebraic proof data + Merkle openings.
///
/// This is the output of [`zk_hadamard_product_proof`] and input to [`verify_zk_hadamard_product`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct ZkHadamardTotalProof<GC: IopCtx, Code>
where
    Code: MultiplicativeCode<GC::EF> + ZkCode<GC::EF>,
{
    pub(in crate::zk::hadamard_product) proof: ZkHadamardProductProof<GC, Code>,
    pub(in crate::zk::hadamard_product) proximity_check_proof: MerkleOpeningProof<GC>,
}

/// Complete Hadamard + dot product proof: both algebraic proofs + shared Merkle openings.
///
/// This is the output of [`zk_hadamard_and_dots_proof`] and input to [`verify_zk_hadamard_and_dots`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct ZkHadamardAndDotsTotalProof<GC: IopCtx, Code>
where
    Code: MultiplicativeCode<GC::EF> + ZkCode<GC::EF>,
{
    pub(in crate::zk::hadamard_product) hadamard_proof: ZkHadamardProductProof<GC, Code>,
    pub(in crate::zk::hadamard_product) dot_proof: ZkDotProductProof<GC, Code>,
    pub(in crate::zk::hadamard_product) proximity_check_proof: MerkleOpeningProof<GC>,
}

impl<GC: IopCtx, Code> ZkHadamardAndDotsTotalProof<GC, Code>
where
    Code: MultiplicativeCode<GC::EF> + ZkCode<GC::EF>,
{
    /// Returns the claimed dot products from the dot product sub-proof.
    pub fn dot_claimed_dot_products(&self) -> &[GC::EF] {
        &self.dot_proof.claimed_dot_products
    }
}

/// Prover secret data needed to generate the proof from commitment.
///
/// Contains the batched [a, b, c, r_+] commitment data plus the multiplicative mask r_×.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct ZkHadamardProductProverSecretData<GC: IopCtx, ProverData, Code>
where
    Code: MultiplicativeCode<GC::EF> + ZkCode<GC::EF>,
{
    pub(in crate::zk::hadamard_product) abc_commitment_data:
        ZkVectorProverData<GC, ProverData, Code>,
    /// Padded r'_× in intermediate form (length 2 * pml.next_power_of_two())
    pub(in crate::zk::hadamard_product) r_times_intermediate: Vec<GC::EF>,
}

/// Intermediate state after computing gamma, phi but before revealing evaluations.
#[derive(Debug, Clone)]
pub(in crate::zk::hadamard_product) struct ZkHadamardProductPreReveal<GC: IopCtx, ProverData, Code>
where
    Code: MultiplicativeCode<GC::EF> + ZkCode<GC::EF>,
{
    pub(in crate::zk::hadamard_product) gamma: GC::EF,
    pub(in crate::zk::hadamard_product) phi: Vec<GC::EF>,
    pub(in crate::zk::hadamard_product) abc_commitment_data:
        ZkVectorProverData<GC, ProverData, Code>,
    pub(in crate::zk::hadamard_product) parameters: CodeParametersForZk<GC::EF, Code>,
}

/// Commits to the three input vectors for zero-knowledge Hadamard product.
///
/// Encodes [a, b, c] as a single batch with additive mask r_+ (width = 4),
/// and r_× separately with product code C*. Both tensors share one Merkle tree.
#[allow(clippy::type_complexity)]
pub fn zk_hadamard_product_commitment<
    GC: IopCtx,
    MK: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
    RNG: CryptoRng + Rng,
    Code: MultiplicativeCode<GC::EF> + ZkCode<GC::EF>,
>(
    a_vec: &[GC::EF],
    b_vec: &[GC::EF],
    c_vec: &[GC::EF],
    rng: &mut RNG,
    merkleizer: &MK,
) -> (GC::Digest, ZkHadamardProductProverSecretData<GC, MK::ProverData, Code>)
where
    rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
{
    let n = a_vec.len();
    assert_eq!(b_vec.len(), n, "b_vec must have the same length as a_vec");
    assert_eq!(c_vec.len(), n, "c_vec must have the same length as a_vec");
    assert!(n > 0, "Vectors must have positive length");

    // Step 1: Encode [a, b, c] with base code C + additive mask r_+
    let (abc_tensor, secrets) = zk_vector_encode::<GC, RNG, Code>(
        &[a_vec.to_vec(), b_vec.to_vec(), c_vec.to_vec()],
        rng,
        &EVAL_SCHEDULE,
    );
    let parameters = secrets.parameters; // [code_length, 4*d]

    // Step 2: Generate r_× and encode with product code C*
    let pml = parameters.padded_message_length;
    let intermediate_len = 2 * pml.next_power_of_two();
    let mut r_times_intermediate: Vec<GC::EF> = repeat_with(|| rng.gen()).take(2 * pml).collect();
    r_times_intermediate.resize(intermediate_len, GC::EF::zero());

    let r_times_codeword = Code::encode_square(&r_times_intermediate, parameters.code_length, pml);
    let r_times_tensor: Tensor<GC::F> =
        RowMajorMatrix::new(r_times_codeword, 1).flatten_to_base().into();
    // Shape: [code_length, d]

    // Step 3: Build message with both tensors and merkleize
    let to_merkleize_message: Message<Tensor<GC::F>> = vec![abc_tensor, r_times_tensor].into();
    let (commitment, merkle_tree) =
        merkleizer.commit_tensors(to_merkleize_message.clone()).unwrap();

    // Step 4: Build commitment data
    let abc_commitment_data = ZkVectorProverData {
        merkle_tree,
        in_vecs: secrets.in_vecs,
        padding: secrets.padding,
        masks: secrets.masks,
        to_merkleize_message,
        parameters,
    };

    let prover_secret_data =
        ZkHadamardProductProverSecretData { abc_commitment_data, r_times_intermediate };

    (commitment, prover_secret_data)
}

/// First phase of the zero-knowledge Hadamard product proof.
///
/// Fiat-Shamir sequence: observe commitment -> sample z_base -> observe gamma -> sample rho_times -> observe phi.
///
/// gamma = u · D(r'_×)[0..n] where u = [1, z_base, z_base^2, ...]
/// phi = (C*)^{-1}(Ca' · Cb' - Cc' + rho_times · C*r'_×)
#[allow(clippy::type_complexity)]
pub(in crate::zk::hadamard_product) fn zk_hadamard_product_pre_reveal<
    GC: IopCtx,
    ProverData,
    Code,
>(
    commitment: GC::Digest,
    prover_secret_data: ZkHadamardProductProverSecretData<GC, ProverData, Code>,
    challenger: &mut GC::Challenger,
) -> ZkHadamardProductPreReveal<GC, ProverData, Code>
where
    GC::EF: TwoAdicField,
    Code: MultiplicativeCode<GC::EF> + ZkCode<GC::EF>,
{
    let ZkHadamardProductProverSecretData { abc_commitment_data, r_times_intermediate } =
        prover_secret_data;
    let parameters = abc_commitment_data.parameters;
    let pml = parameters.padded_message_length;
    let n = abc_commitment_data.in_vecs[0].len();

    // Round 1: Observe commitment, sample z_base
    challenger.observe(commitment);
    let z_base: GC::EF = challenger.sample_ext_element();
    let u: Vec<GC::EF> = z_base.powers().take(n).collect();

    // Round 2: Compute gamma = u · D(r'_×)[0..n], observe gamma, sample rho_times
    let r_times_red = Code::square_to_base(&r_times_intermediate, parameters.code_length, pml);
    let gamma: GC::EF = dot_product(&u, &r_times_red[..n]);
    challenger.observe_ext_element(gamma);
    let rho_times: GC::EF = challenger.sample_ext_element();

    // Round 3: Compute phi from codewords, observe phi
    // phi = (C*)^{-1}(Ca' · Cb' - Cc' + rho_times · C*r'_×)
    let abc_ef =
        abc_commitment_data.to_merkleize_message[0].as_ref().clone().into_extension::<GC::EF>();
    let rtx_ef =
        abc_commitment_data.to_merkleize_message[1].as_ref().clone().into_extension::<GC::EF>();
    let abc_s = abc_ef.as_slice();
    let rtx_s = rtx_ef.as_slice();

    let code_length = parameters.code_length;
    let product_codeword: Vec<GC::EF> = (0..code_length)
        .map(|i| {
            let a_hat = abc_s[i * 4];
            let b_hat = abc_s[i * 4 + 1];
            let c_hat = abc_s[i * 4 + 2];
            let r_times_hat = rtx_s[i];
            a_hat * b_hat - c_hat + rho_times * r_times_hat
        })
        .collect();

    let phi = Code::decode_square(&product_codeword, pml);

    challenger.observe_ext_element_slice(&phi);

    ZkHadamardProductPreReveal { gamma, phi, abc_commitment_data, parameters }
}

/// Second phase of the zero-knowledge Hadamard product proof: reveal evaluations and generate merkle proofs.
///
/// Returns the proof and the revealed data.
pub(in crate::zk::hadamard_product) fn zk_hadamard_product_reveal<
    GC: IopCtx,
    MK: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
    Code: MultiplicativeCode<GC::EF> + ZkCode<GC::EF>,
>(
    pre_reveal: ZkHadamardProductPreReveal<GC, MK::ProverData, Code>,
    revealed_indices: &[usize],
    merkleizer: &MK,
) -> (ZkHadamardProductProof<GC, Code>, MerkleOpeningProof<GC>) {
    let ZkHadamardProductPreReveal { gamma, phi, abc_commitment_data, parameters } = pre_reveal;

    let revealed_evals = merkleizer
        .compute_openings_at_indices(abc_commitment_data.to_merkleize_message, revealed_indices);
    let merkle_paths = merkleizer
        .prove_openings_at_indices(abc_commitment_data.merkle_tree, revealed_indices)
        .unwrap();

    let proof = ZkHadamardProductProof { gamma, phi, parameters };
    let revealed_data = MerkleOpeningProof { revealed_evals, merkle_paths };

    (proof, revealed_data)
}

/// Generates the zero-knowledge Hadamard product proof (standalone, without dot products).
///
/// Returns the proof and the revealed data (Merkle openings).
#[allow(clippy::type_complexity)]
pub fn zk_hadamard_product_proof<
    GC: IopCtx,
    MK: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
    Code: MultiplicativeCode<GC::EF> + ZkCode<GC::EF>,
>(
    commitment: GC::Digest,
    prover_secret_data: ZkHadamardProductProverSecretData<GC, MK::ProverData, Code>,
    challenger: &mut GC::Challenger,
    merkleizer: &MK,
) -> ZkHadamardTotalProof<GC, Code>
where
    GC::EF: TwoAdicField,
{
    let pre_reveal = zk_hadamard_product_pre_reveal(commitment, prover_secret_data, challenger);
    let revealed_indices =
        repeat_with(|| challenger.sample_bits(pre_reveal.parameters.code_log_length))
            .take(pre_reveal.parameters.multi_evals(&EVAL_SCHEDULE))
            .collect::<Vec<_>>();
    let (proof, revealed_data) =
        zk_hadamard_product_reveal(pre_reveal, &revealed_indices, merkleizer);
    ZkHadamardTotalProof { proof, proximity_check_proof: revealed_data }
}

/// Combined proof for Hadamard product and a batched dot product with shared indices.
///
/// Generates proofs for both the Hadamard product relation (a * b = c)
/// and the dot product of each vector (a, b, c) with `dot_vec`,
/// using a single set of revealed indices for soundness.
///
/// Returns the Hadamard proof, the dot product proof, and a single shared [`MerkleOpeningProof`].
#[allow(clippy::type_complexity)]
pub fn zk_hadamard_and_dots_proof<
    GC: IopCtx,
    MK: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
    Code: MultiplicativeCode<GC::EF> + ZkCode<GC::EF>,
>(
    commitment: GC::Digest,
    dot_vec: &[GC::EF],
    prover_secret_data: ZkHadamardProductProverSecretData<GC, MK::ProverData, Code>,
    challenger: &mut GC::Challenger,
    merkleizer: &MK,
) -> ZkHadamardAndDotsTotalProof<GC, Code>
where
    GC::EF: TwoAdicField,
{
    // Phase 1a: Hadamard pre-reveal
    let hadamard_pre = zk_hadamard_product_pre_reveal(commitment, prover_secret_data, challenger);

    // Destructure to avoid expensive clone of the full abc_commitment_data.
    // We only need a cheap Arc-bumped clone of the message for Merkle openings later.
    let ZkHadamardProductPreReveal { gamma, phi, abc_commitment_data, parameters } = hadamard_pre;
    let to_merkleize_message = abc_commitment_data.to_merkleize_message.clone();

    // Phase 1b: Dot product pre-reveal — move abc_commitment_data instead of cloning
    let dot_pre_reveal: ZkDotProductPreReveal<GC, MK::ProverData, Code> =
        zk_dot_product_pre_reveal(dot_vec, &commitment, abc_commitment_data, challenger);

    // Phase 2: Sample indices (single sampling point for all proofs)
    let revealed_indices = repeat_with(|| challenger.sample_bits(parameters.code_log_length))
        .take(parameters.multi_evals(&EVAL_SCHEDULE))
        .collect::<Vec<_>>();

    // Phase 3: Compute Merkle openings once for all proofs.
    // Use the Arc-cloned message (cheap) and extract merkle_tree from dot_pre_reveal (moved, no clone).
    let revealed_evals =
        merkleizer.compute_openings_at_indices(to_merkleize_message, &revealed_indices);
    let merkle_paths = merkleizer
        .prove_openings_at_indices(dot_pre_reveal.merkle_tree, &revealed_indices)
        .unwrap();

    // Build Hadamard proof (no revealed data — it's in the shared ZkRevealedData)
    let hadamard_proof = ZkHadamardProductProof { gamma, phi, parameters };

    // Build dot product proof (no revealed data — it's in the shared ZkRevealedData)
    let dot_proof = ZkDotProductProof {
        claimed_dot_products: dot_pre_reveal.claimed_dot_products,
        mask_dot_product: dot_pre_reveal.mask_dot_product,
        rlc_vec: dot_pre_reveal.rlc_vec,
        rlc_padding: dot_pre_reveal.rlc_padding,
        parameters: dot_pre_reveal.parameters,
    };

    let revealed_data = MerkleOpeningProof { revealed_evals, merkle_paths };

    ZkHadamardAndDotsTotalProof { hadamard_proof, dot_proof, proximity_check_proof: revealed_data }
}

/// Computes the Hadamard (elementwise) product of two vectors.
pub fn hadamard_product<K>(a_vec: &[K], b_vec: &[K]) -> Vec<K>
where
    K: AbstractField + Copy,
{
    a_vec.iter().zip_eq(b_vec.iter()).map(|(a, b)| *a * *b).collect()
}
