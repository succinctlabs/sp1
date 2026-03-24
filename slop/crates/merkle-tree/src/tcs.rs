use std::error::Error;
use std::fmt::Debug;

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractField, PrimeField32};
use slop_alloc::Backend;
use slop_challenger::IopCtx;
use slop_commit::Message;
use slop_futures::OwnedBorrow;
use slop_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use slop_tensor::Tensor;

/// Trait for tensor commitment scheme provers.
pub trait TensorCsProver<GC: IopCtx, A: Backend>: 'static + Send + Sync {
    type ProverData: 'static + Send + Sync + Debug + Clone;
    type ProverError: Error;

    /// Commit to a batch of tensors of the same shape.
    ///
    /// The prover is free to choose which dimension index is supported.
    #[allow(clippy::type_complexity)]
    fn commit_tensors<T>(
        &self,
        tensors: Message<T>,
    ) -> Result<(GC::Digest, Self::ProverData), Self::ProverError>
    where
        T: OwnedBorrow<Tensor<GC::F, A>>;

    /// Prove openings at a list of indices.
    fn prove_openings_at_indices(
        &self,
        data: Self::ProverData,
        indices: &[usize],
    ) -> Result<MerkleTreeTcsProof<GC::Digest>, Self::ProverError>;
}

/// Trait for computing openings at indices.
pub trait ComputeTcsOpenings<GC: IopCtx, A: Backend>: TensorCsProver<GC, A> {
    fn compute_openings_at_indices<T>(
        &self,
        tensors: Message<T>,
        indices: &[usize],
    ) -> Tensor<GC::F>
    where
        T: OwnedBorrow<Tensor<GC::F, A>>;
}

/// An opening of a tensor commitment scheme.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MerkleTreeOpeningAndProof<GC: IopCtx> {
    /// The claimed values of the opening.
    pub values: Tensor<GC::F>,
    /// The proof of the opening.
    pub proof: MerkleTreeTcsProof<GC::Digest>,
}

/// A merkle tree Tensor commitment scheme.
///
/// A tensor commitment scheme based on merkleizing the committed tensors at a given dimension,
/// which the prover is free to choose.
#[derive(Debug, Clone, Copy)]
pub struct MerkleTreeTcs<GC: IopCtx> {
    pub hasher: GC::Hasher,
    pub compressor: GC::Compressor,
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum MerkleTreeTcsError {
    #[error("root mismatch")]
    RootMismatch,
    #[error("proof has incorrect shape")]
    IncorrectShape,
    #[error("incorrect width or height")]
    InconsistentCommitmentShape,
    #[error("base field overflow")]
    BaseFieldOverflow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTreeTcsProof<T> {
    pub merkle_root: T,
    pub log_tensor_height: usize,
    pub width: usize,
    pub paths: Tensor<T>,
}

impl<GC: IopCtx> Default for MerkleTreeTcs<GC> {
    #[inline]
    fn default() -> Self {
        let (hasher, compressor) = GC::default_hasher_and_compressor();
        Self { hasher, compressor }
    }
}

impl<GC: IopCtx> MerkleTreeTcs<GC> {
    pub fn verify_tensor_openings(
        &self,
        commit: &GC::Digest,
        indices: &[usize],
        opening: &Tensor<GC::F>,
        proof: &MerkleTreeTcsProof<GC::Digest>,
    ) -> Result<(), MerkleTreeTcsError> {
        let expected_path_len = proof.log_tensor_height;
        if proof.paths.dimensions.sizes().len() != 2 || opening.dimensions.sizes().len() != 2 {
            return Err(MerkleTreeTcsError::IncorrectShape);
        }
        if indices.len() != proof.paths.dimensions.sizes()[0] {
            return Err(MerkleTreeTcsError::IncorrectShape);
        }
        if indices.len() != opening.dimensions.sizes()[0] {
            return Err(MerkleTreeTcsError::IncorrectShape);
        }

        for (i, (index, path)) in indices.iter().zip_eq(proof.paths.split()).enumerate() {
            // Collect the lead slices of the claimed values.
            let claimed_values_slices = opening.get(i).unwrap().as_slice();
            // Check that the proof is the correct length.
            if claimed_values_slices.len() != proof.width {
                return Err(MerkleTreeTcsError::IncorrectShape);
            }

            let path = path.as_slice();

            // Iterate the path and compute the root.
            let digest = self.hasher.hash_iter_slices(vec![claimed_values_slices]);

            let mut root = digest;
            let mut index = *index;

            if path.len() != expected_path_len {
                return Err(MerkleTreeTcsError::IncorrectShape);
            }

            for sibling in path.iter().cloned() {
                let (left, right) = if index & 1 == 0 { (root, sibling) } else { (sibling, root) };
                root = self.compressor.compress([left, right]);
                index >>= 1;
            }

            if root != proof.merkle_root {
                return Err(MerkleTreeTcsError::RootMismatch);
            }

            if index != 0 {
                return Err(MerkleTreeTcsError::IncorrectShape);
            }
        }

        if proof.log_tensor_height >= GC::F::ORDER_U32 as usize
            || proof.width >= GC::F::ORDER_U32 as usize
        {
            return Err(MerkleTreeTcsError::BaseFieldOverflow);
        }

        // Hash the proof metadata in with the Merkle root to get the expected commitment.
        let hash = self.hasher.hash_slice(&[
            GC::F::from_canonical_usize(proof.log_tensor_height),
            GC::F::from_canonical_usize(proof.width),
        ]);
        let expected_commit = self.compressor.compress([proof.merkle_root, hash]);

        if expected_commit != *commit {
            return Err(MerkleTreeTcsError::InconsistentCommitmentShape);
        }

        Ok(())
    }
}
