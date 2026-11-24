use std::error::Error;
use std::fmt::Debug;

use rayon::prelude::*;
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
    #[error("width or height inconsistent with commitment")]
    InconsistentCommitmentShape,
    #[error("incorrect log height: expected {expected}, got {actual}")]
    IncorrectLogHeight { expected: usize, actual: usize },
    #[error("incorrect width: expected {expected}, got {actual}")]
    IncorrectWidth { expected: usize, actual: usize },
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
        expected_width: usize,
        expected_log_height: usize,
        proof: &MerkleTreeTcsProof<GC::Digest>,
    ) -> Result<(), MerkleTreeTcsError> {
        if proof.width != expected_width {
            return Err(MerkleTreeTcsError::IncorrectWidth {
                expected: expected_width,
                actual: proof.width,
            });
        }
        if proof.log_tensor_height != expected_log_height {
            return Err(MerkleTreeTcsError::IncorrectLogHeight {
                expected: expected_log_height,
                actual: proof.log_tensor_height,
            });
        }

        let expected_path_len = proof.log_tensor_height;
        if !proof.paths.has_valid_shape()
            || !opening.has_valid_shape()
            || proof.paths.dimensions.sizes().len() != 2
            || opening.dimensions.sizes().len() != 2
        {
            return Err(MerkleTreeTcsError::IncorrectShape);
        }
        if indices.len() != proof.paths.dimensions.sizes()[0] {
            return Err(MerkleTreeTcsError::IncorrectShape);
        }
        if indices.len() != opening.dimensions.sizes()[0] {
            return Err(MerkleTreeTcsError::IncorrectShape);
        }

        let mut order: Vec<_> = (0..indices.len()).collect();
        order.sort_unstable_by_key(|&i| indices[i]);
        order.par_chunks(8).try_for_each(|chunk| {
            let mut ancestors = Vec::with_capacity(expected_path_len.saturating_add(1));
            let mut previous = None::<usize>;
            for &i in chunk {
                let values = opening.get(i).unwrap().as_slice();
                let path = proof.paths.get(i).unwrap().as_slice();
                let mut index = indices[i];
                if values.len() != proof.width
                    || path.len() != expected_path_len
                    || (usize::BITS - index.leading_zeros()) as usize > expected_path_len
                {
                    return Err(MerkleTreeTcsError::IncorrectShape);
                }
                let mut root = self.hasher.hash_slice(values);
                // Adjacent leaves often share the upper path. Reuse a checked suffix only
                // when both its input digest and every supplied sibling match.
                let common =
                    previous.map(|j| (usize::BITS - (index ^ indices[j]).leading_zeros()) as usize);
                for level in 0..=path.len() {
                    if common == Some(level)
                        && root == ancestors[level]
                        && path[level..]
                            == proof.paths.get(previous.unwrap()).unwrap().as_slice()[level..]
                    {
                        root = proof.merkle_root;
                        break;
                    }
                    if previous.is_some() {
                        ancestors[level] = root;
                    } else {
                        ancestors.push(root);
                    }
                    if level == path.len() {
                        break;
                    }
                    let sibling = path[level];
                    let pair = if index & 1 == 0 { [root, sibling] } else { [sibling, root] };
                    root = self.compressor.compress(pair);
                    index >>= 1;
                }
                if root != proof.merkle_root {
                    return Err(MerkleTreeTcsError::RootMismatch);
                }
                previous = Some(i);
            }
            Ok(())
        })?;

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
