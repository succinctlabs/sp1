//! Zero-knowledge-aware wrapper for [`BasefoldProver`] with custom encoding support.

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
