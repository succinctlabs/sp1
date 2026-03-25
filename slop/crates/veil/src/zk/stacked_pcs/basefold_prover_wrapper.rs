//! Zero-knowledge-aware wrapper for [`BasefoldProver`] with custom batching support.
//!
//!
//! This module provides utilities to work with [`BasefoldProver`] while injecting
//! custom batching logic that operates on extension field MLEs. This is necessary
//! for zero-knowledge protocols where masking polynomials need to be incorporated
//! during the batching phase.
//!
//! # Overview
//!
//! The standard `BasefoldProver::prove_trusted_mle_evaluations` function takes MLEs
//! over the base field `GC::F` and internally performs batching to convert them to
//! extension field `GC::EF` before running the core Basefold protocol. This module
//! factors out that conversion, providing two key utilities:
//!
//! 1. **`ZkBasefoldProver`**: A wrapper struct around `BasefoldProver` that implements
//!    both `MultilinearPcsBatchProver` and `ZkMultilinearPcsBatchProver`, providing
//!    a clean interface for working with custom batching.
//!
//! 2. **`prove_from_batched_inputs`**: A standalone function that runs the Basefold
//!    protocol starting from already-batched extension field inputs. This allows you
//!    to implement custom batching logic (e.g., with masking polynomials) while
//!    reusing all the Basefold infrastructure.
//!
//! # Usage Example
//!
//! ```ignore
//! use slop_basefold_prover::{BasefoldProver, BasefoldProverComponents};
//! use veil::{ZkBasefoldProver, ZkMultilinearPcsBatchProver, prove_from_batched_inputs};
//!
//! // Create your standard BasefoldProver
//! let basefold_prover: BasefoldProver<GC, C> = /* ... */;
//!
//! // Wrap it to get ZK capabilities
//! let zk_prover = ZkBasefoldProver::new(basefold_prover);
//!
//! // The wrapper implements MultilinearPcsBatchProver, so you can use it
//! // for standard commitment operations
//! let (commitment, prover_data) = zk_prover.commit_multilinears(mles)?;
//!
//! // Implement your custom batching logic here
//! let (batched_mle, batched_codeword, batched_eval_claim) =
//!     my_custom_zk_batching(data_mles, masking_mles, evaluations, challenger);
//!
//! // Option 1: Use the helper method (equivalent to Option 1)
//! let proof = zk_prover.prove_with_batched_ef_inputs(
//!     eval_point,
//!     batched_mle,
//!     batched_eval_claim,
//!     prover_data,
//!     challenger,
//! )?;
//!
//! // Option 2: Use the standalone function directly
//! let proof = prove_from_batched_inputs(
//!     zk_prover.basefold_prover(),
//!     eval_point,
//!     batched_mle,
//!     batched_eval_claim,
//!     prover_data,
//!     challenger,
//! )?;
//! ```
//!
//! # Custom Batching Pattern
//!
//! To implement ZK-aware batching:
//!
//! 1. **Convert to extension field**: Convert your base field MLEs to extension field
//! 2. **Add masking**: Incorporate masking polynomials for zero-knowledge
//! 3. **Random linear combination**: Compute batched MLE as:
//!    ```text
//!    batched_mle = Σ(α^i · data_mle_i) + Σ(α^(n+j) · mask_mle_j)
//!    ```
//!    where α is the batching challenge
//! 4. **Encode**: Reed-Solomon encode the batched MLE to get batched codeword
//! 5. **Compute claim**: Compute the batched evaluation claim similarly
//!
//! See `basefold-prover/src/fri.rs::FriCpuProver::batch` for the standard batching
//! implementation that you can adapt for ZK.

use crate::zk::inner::{MerkleProverData, ZkIopCtx, ZkMerkleizer};
use itertools::Itertools;
use slop_algebra::AbstractField;
use slop_alloc::CpuBackend;
use slop_basefold::{BasefoldProof, RsCodeWord};
use slop_basefold_prover::{
    BaseFoldConfigProverError, BasefoldProver, BasefoldProverData, BasefoldProverError,
    FriCpuProver,
};
use slop_challenger::{CanSampleBits, FieldChallenger, GrindingChallenger};
use slop_commit::Message;
use slop_dft::{Dft, DftOrdering};
use slop_futures::OwnedBorrow;
use slop_matrix::dense::RowMajorMatrix;
use slop_merkle_tree::MerkleTreeOpeningAndProof;
use slop_multilinear::{Mle, Point};
use slop_tensor::Tensor;
use std::{marker::PhantomData, sync::Arc};

/// Core function that proves evaluations starting from already-batched extension field inputs.
///
/// This function factors out the post-batching logic from `BasefoldProver::prove_trusted_mle_evaluations`,
/// allowing custom batching strategies to be used while reusing the core Basefold proving protocol.
///
/// # Parameters
/// - `basefold_prover`: Reference to the underlying BasefoldProver
/// - `eval_point`: The evaluation point in the extension field
/// - `batched_mle`: Pre-batched MLE over the extension field GC::EF
/// - `batched_codeword`: Pre-batched Reed-Solomon codeword
/// - `batched_eval_claim`: The batched evaluation claim
/// - `prover_data`: Prover data from committing the unbatched ORIGINAL MLEs
/// - `challenger`: The Fiat-Shamir challenger
///
/// # Returns
/// A BasefoldProof or an error
/// The commitments in the basefold proof correspond to the Merkleization of the basefield components of the extension field MLE
#[allow(clippy::type_complexity)]
pub fn prove_from_batched_inputs<GC: ZkIopCtx, MK: ZkMerkleizer<GC>>(
    basefold_prover: &BasefoldProver<GC, MK>,
    mut eval_point: Point<GC::EF>,
    batched_mle: Mle<GC::EF, CpuBackend>,
    batched_eval_claim: GC::EF,
    batched_codeword: RsCodeWord<GC::F, CpuBackend>,
    prover_datas: Vec<BasefoldProverData<GC::F, MerkleProverData<GC, MK>>>,
    challenger: &mut GC::Challenger,
) -> Result<BasefoldProof<GC>, BaseFoldConfigProverError<GC, MK>> {
    let fri_prover = FriCpuProver::<GC, MK>(PhantomData);

    let mut current_mle = batched_mle;
    let mut current_codeword = batched_codeword;

    // Initialize the vecs that go into a BaseFoldProof.
    let log_len = current_mle.num_variables();
    let mut univariate_messages: Vec<[GC::EF; 2]> = vec![];
    let mut fri_commitments = vec![];
    let mut commit_phase_data = vec![];
    let mut current_batched_eval_claim = batched_eval_claim;
    let mut commit_phase_values = vec![];

    assert_eq!(
        current_mle.num_variables(),
        eval_point.dimension() as u32,
        "eval point dimension mismatch"
    );

    // Main Basefold reduction loop
    for _ in 0..eval_point.dimension() {
        // Compute claims for `g(X_0, X_1, ..., X_{d-1}, 0)` and `g(X_0, X_1, ..., X_{d-1}, 1)`.
        let last_coord = eval_point.remove_last_coordinate();
        let zero_values = current_mle.fixed_at_zero(&eval_point);
        let zero_val = zero_values[0];
        let one_val = (current_batched_eval_claim - zero_val) / last_coord + zero_val;
        let uni_poly = [zero_val, one_val];
        univariate_messages.push(uni_poly);

        uni_poly.iter().for_each(|elem| challenger.observe_ext_element(*elem));

        // Perform a single round of the FRI commit phase, returning the commitment, folded
        // codeword, and folding parameter.
        let (beta, folded_mle, folded_codeword, commitment, leaves, prover_data_round) = fri_prover
            .commit_phase_round(
                current_mle,
                current_codeword,
                &basefold_prover.tcs_prover,
                challenger,
            )
            .map_err(BasefoldProverError::CommitPhaseError)?;

        fri_commitments.push(commitment);
        commit_phase_data.push(prover_data_round);
        commit_phase_values.push(leaves);

        current_mle = folded_mle;
        current_codeword = folded_codeword;
        current_batched_eval_claim = zero_val + beta * one_val;
    }

    // Finalize the constant polynomial
    let final_poly = fri_prover.final_poly(current_codeword);
    challenger.observe_ext_element(final_poly);

    // Proof of work
    let fri_config = basefold_prover.encoder.config();
    let pow_bits = fri_config.proof_of_work_bits;
    let pow_witness = challenger.grind(pow_bits);

    // FRI Query Phase.
    let query_indices: Vec<usize> = (0..fri_config.num_queries)
        .map(|_| challenger.sample_bits(log_len as usize + fri_config.log_blowup()))
        .collect();

    // Open each committed polynomial at the query indices.
    let mut component_polynomials_query_openings_and_proofs = vec![];
    for prover_data in prover_datas {
        let BasefoldProverData { encoded_messages, tcs_prover_data } = prover_data;
        let values = basefold_prover
            .tcs_prover
            .compute_openings_at_indices(encoded_messages, &query_indices);
        let proof = basefold_prover
            .tcs_prover
            .prove_openings_at_indices(tcs_prover_data, &query_indices)
            .map_err(BaseFoldConfigProverError::<GC, MK>::TcsCommitError)
            .unwrap();
        component_polynomials_query_openings_and_proofs
            .push(MerkleTreeOpeningAndProof::<GC> { values, proof });
    }

    // Provide openings for the FRI query phase.
    let mut query_phase_openings_and_proofs = vec![];
    let mut indices = query_indices;
    for (leaves, data) in commit_phase_values.into_iter().zip_eq(commit_phase_data) {
        for index in indices.iter_mut() {
            *index >>= 1;
        }
        let leaves: Message<Tensor<GC::F, CpuBackend>> = leaves.into();
        let values = basefold_prover.tcs_prover.compute_openings_at_indices(leaves, &indices);

        let proof = basefold_prover
            .tcs_prover
            .prove_openings_at_indices(data, &indices)
            .map_err(BaseFoldConfigProverError::<GC, MK>::TcsCommitError)?;
        let opening = MerkleTreeOpeningAndProof { values, proof };
        query_phase_openings_and_proofs.push(opening);
    }

    Ok(BasefoldProof {
        univariate_messages,
        fri_commitments,
        component_polynomials_query_openings_and_proofs,
        query_phase_openings_and_proofs,
        final_poly,
        pow_witness,
    })
}

/// A wrapper around BasefoldProver that enables custom batching strategies.
///
/// This wrapper allows zero-knowledge protocols to inject their own batching logic
/// while reusing the core Basefold proving infrastructure. The key difference from
/// the standard BasefoldProver is that batching happens over extension field MLEs
/// and can incorporate masking polynomials.
///
/// # Type Constraints
/// This struct requires:
/// - `C::A = CpuBackend`: Only CPU backend is supported
/// - `C::Encoder = CpuDftEncoder<GC::F, Radix2DitParallel>`: Encoder must use Radix2DitParallel DFT
#[derive(Clone)]
pub struct ZkBasefoldProver<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> {
    /// The underlying BasefoldProver instance
    pub inner: BasefoldProver<GC, MK>,
}

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> ZkBasefoldProver<GC, MK> {
    /// Create a new ZkBasefoldProver wrapping a BasefoldProver
    pub fn new(inner: BasefoldProver<GC, MK>) -> Self {
        Self { inner }
    }

    /// Prove evaluations using custom pre-batched inputs over the extension field.
    ///
    /// This is the main entry point for ZK protocols. Instead of taking base field MLEs
    /// and batching them internally, this function accepts pre-batched extension field
    /// inputs, allowing the caller to implement custom batching logic (e.g., incorporating
    /// masking polynomials for zero-knowledge).
    ///
    /// # Parameters
    /// - `eval_point`: The evaluation point in the extension field
    /// - `batched_mle`: Pre-batched MLE over GC::EF (may include masking)
    /// - `batched_codeword`: Corresponding Reed-Solomon encoded codeword
    /// - `batched_eval_claim`: The claimed evaluation
    /// - `prover_data`: Prover data from commitment phase
    /// - `challenger`: Fiat-Shamir challenger
    pub fn prove_with_batched_ef_inputs(
        &self,
        eval_point: Point<GC::EF>,
        batched_mle: Mle<GC::EF, CpuBackend>,
        batched_codeword: RsCodeWord<GC::F, CpuBackend>,
        batched_eval_claim: GC::EF,
        prover_datas: Vec<BasefoldProverData<GC::F, MerkleProverData<GC, MK>>>,
        challenger: &mut GC::Challenger,
    ) -> Result<BasefoldProof<GC>, BaseFoldConfigProverError<GC, MK>> {
        prove_from_batched_inputs(
            &self.inner,
            eval_point,
            batched_mle,
            batched_eval_claim,
            batched_codeword,
            prover_datas,
            challenger,
        )
    }

    /// Encode MLEs with an arbitrary log_blowup factor.
    ///
    /// This function performs Reed-Solomon encoding on the input MLEs using a custom
    /// blowup factor, bypassing the encoder's configured log_blowup. This is useful when
    /// you need different rate codes for different parts of the protocol.
    ///
    /// # Parameters
    /// - `data`: The MLEs to encode (as a Message of Mle<F, A>)
    /// - `log_blowup`: The logarithm (base 2) of the blowup factor to use
    ///
    /// # Returns
    /// A Message of RsCodeWord containing the encoded codewords
    ///
    /// # Implementation
    /// This copies the logic from `CpuDftEncoder::encode_batch` but allows passing
    /// a custom log_blowup instead of using the one from the FRI config.
    pub fn encode_with_log_blowup(
        &self,
        data: Message<impl OwnedBorrow<Mle<GC::F, CpuBackend>>>,
        log_blowup: usize,
    ) -> Message<RsCodeWord<GC::F, CpuBackend>> {
        // Synchronous version of CpuDftEncoder::encode_batch with custom log_blowup
        let dft = self.inner.encoder.dft.clone();
        let data = data.to_vec();

        let mut results = Vec::with_capacity(data.len());
        for data in data {
            let data = data.borrow().guts();
            assert_eq!(data.sizes().len(), 2, "Expected a 2D tensor");
            // Perform a DFT along the first axis of the tensor (assumed to be the long
            // dimension).
            let dft_result = dft.dft(data, log_blowup, DftOrdering::BitReversed, 0).unwrap();
            results.push(Arc::new(RsCodeWord { data: dft_result }));
        }
        Message::from(results)
    }

    /// Commit to MLEs with padding and reduced blowup factor.
    ///
    /// This function:
    /// 1. Pads each MLE's length to the next power of two (with zeros)
    /// 2. Encodes using log_blowup - 1 instead of the configured log_blowup
    /// 3. Commits the encoded codewords
    ///
    /// # Parameters
    /// - `mles`: The MLEs to commit
    ///
    /// # Returns
    /// A tuple of (commitment digest, prover data)
    ///
    /// # Implementation
    /// The padding ensures that each MLE has a power-of-two length, which is often
    /// required for efficient FFT operations. The reduced blowup (log_blowup - 1)
    /// ensures the outputs stay the same size as a normal unpadded commitment
    #[allow(clippy::type_complexity)]
    pub fn commit_padded_multilinears(
        &self,
        mles: Message<Mle<GC::F, CpuBackend>>,
    ) -> Result<
        (GC::Digest, BasefoldProverData<GC::F, MerkleProverData<GC, MK>>),
        BaseFoldConfigProverError<GC, MK>,
    > {
        // Pad each MLE to the next power of two
        let padded_mles = mles
            .into_iter()
            .map(|mle| {
                let guts = mle.guts();
                let sizes = guts.sizes();
                assert_eq!(sizes.len(), 2, "Expected a 2D tensor");

                let num_rows = sizes[0];
                let num_cols = sizes[1];

                // Calculate next power of two for the first dimension
                let padded_num_rows = num_rows.next_power_of_two();

                if padded_num_rows == num_rows {
                    // Already a power of two, no padding needed
                    mle
                } else {
                    // Convert to vector, pad with zeros, and reshape
                    let mut padded_vec = guts.clone().into_buffer().into_vec();
                    padded_vec.resize(padded_num_rows * num_cols, GC::F::zero());

                    // Create RowMajorMatrix and convert to Tensor, then to MLE
                    Arc::new(Mle::new(RowMajorMatrix::new(padded_vec, num_cols).into()))
                }
            })
            .collect::<Vec<_>>();

        let padded_mles_message: Message<Mle<GC::F, CpuBackend>> = padded_mles.into();

        // Get the configured log_blowup and reduce by 1
        let config_log_blowup = self.inner.encoder.config().log_blowup();
        let reduced_log_blowup = config_log_blowup.saturating_sub(1);

        // Encode with reduced blowup
        let encoded_messages = self.encode_with_log_blowup(padded_mles_message, reduced_log_blowup);

        // Commit to the encoded messages
        let (commitment, tcs_prover_data) = self
            .inner
            .tcs_prover
            .commit_tensors(encoded_messages.clone())
            .map_err(BaseFoldConfigProverError::<GC, MK>::TcsCommitError)?;

        Ok((commitment, BasefoldProverData { encoded_messages, tcs_prover_data }))
    }
}

// NOTE: Custom batching logic with masking polynomials should be implemented
// by the user of this module. The general pattern is:
//
// 1. Convert base field MLEs to extension field using field embedding
// 2. Generate masking polynomials for zero-knowledge
// 3. Compute random linear combination using batching challenge:
//    batched_mle = sum(challenge^i * data_mle_i) + sum(challenge^(n+j) * mask_mle_j)
// 4. Compute batched evaluation claim similarly
// 5. Encode the batched MLE to get the batched codeword
// 6. Call prove_from_batched_inputs() with these batched values
//
// See basefold-prover/src/fri.rs::FriCpuProver::batch for reference implementation
// of standard (non-ZK) batching.
