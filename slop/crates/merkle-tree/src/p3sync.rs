use std::{
    borrow::Borrow, cmp::Reverse, convert::Infallible, mem::ManuallyDrop, ops::Deref, sync::Arc,
};

use itertools::Itertools;
use p3_merkle_tree::{compress_and_inject, first_digest_layer};
use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractField, PackedField, PackedValue};
use slop_alloc::CpuBackend;
use slop_challenger::IopCtx;
use slop_commit::Message;
use slop_futures::OwnedBorrow;
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use slop_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use slop_tensor::Tensor;

use super::{FieldMerkleTreeDigests, FieldMerkleTreeProver};
use crate::{ComputeTcsOpenings, MerkleTreeTcsProof, TensorCsProver};

impl<P, PW, GC: IopCtx, const DIGEST_ELEMS: usize> TensorCsProver<GC, CpuBackend>
    for FieldMerkleTreeProver<P, PW, GC, DIGEST_ELEMS>
where
    P: PackedField<Scalar = GC::F>,
    PW: PackedValue,
    GC::Digest: Into<[PW::Value; DIGEST_ELEMS]> + From<[PW::Value; DIGEST_ELEMS]>,
    GC::Hasher: CryptographicHasher<P::Scalar, [PW::Value; DIGEST_ELEMS]>
        + CryptographicHasher<P::Scalar, GC::Digest>,
    GC::Hasher: CryptographicHasher<P, [PW; DIGEST_ELEMS]>,
    GC::Hasher: Sync,
    GC::Compressor: PseudoCompressionFunction<[PW::Value; DIGEST_ELEMS], 2>
        + PseudoCompressionFunction<GC::Digest, 2>,
    GC::Compressor: PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>,
    GC::Compressor: Sync,
    PW::Value: Eq + std::fmt::Debug,
    [PW::Value; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
{
    type ProverError = Infallible;
    type ProverData = (FieldMerkleTreeDigests<PW::Value, DIGEST_ELEMS>, GC::Digest, usize, usize);

    fn commit_tensors<T>(
        &self,
        tensors: Message<T>,
    ) -> Result<(GC::Digest, Self::ProverData), Self::ProverError>
    where
        T: OwnedBorrow<Tensor<GC::F, CpuBackend>>,
    {
        let tcs = self.tcs.clone();

        let height =
            Borrow::<Tensor<_>>::borrow(tensors.first().cloned().unwrap().as_ref()).sizes()[0];
        let widths = tensors.iter().map(|t| {
            let t_ref: &T = t.borrow();
            let t_ref: &Tensor<GC::F, CpuBackend> = t_ref.borrow();
            t_ref.sizes()[1]
        });

        let total_width = widths.sum::<usize>();
        assert!(tensors
            .iter()
            .all(|t| Borrow::<Tensor<_>>::borrow(t.as_ref()).sizes()[0] == height));

        let leaves_owned = tensors
            .iter()
            .map(|t| {
                let t_ref: &T = t.borrow();
                let t: &Tensor<GC::F> = t_ref.borrow();
                let ptr = t.as_ptr() as *mut P::Value;
                let height = t.sizes()[0];
                let width = t.sizes()[1];
                let vec = unsafe { Vec::from_raw_parts(ptr, height * width, height * width) };
                let matrix = RowMajorMatrix::new(vec, width);
                ManuallyDrop::new(matrix)
            })
            .collect::<Vec<_>>();
        let leaves = leaves_owned.iter().map(|m| m.deref()).collect::<Vec<_>>();
        assert!(!tensors.is_empty(), "No matrices given?");

        assert_eq!(P::WIDTH, PW::WIDTH, "Packing widths must match");

        // check height property
        assert!(
            leaves
                .iter()
                .map(|m| m.height())
                .sorted()
                .tuple_windows()
                .all(|(curr, next)| curr == next
                    || curr.next_power_of_two() != next.next_power_of_two()),
            "matrix heights that round up to the same power of two must be equal"
        );

        // Sorting the trees by height, but this is expected to be a no-op because of the
        // assertions at the top of the function.

        let mut leaves_largest_first =
            leaves.iter().sorted_by_key(|l| Reverse(l.height())).peekable();

        let max_height = leaves_largest_first.peek().unwrap().height();
        let tallest_matrices = leaves_largest_first
            .peeking_take_while(|m| m.height() == max_height)
            .copied()
            .collect_vec();

        let mut digest_layers =
            vec![first_digest_layer::<P, PW, GC::Hasher, RowMajorMatrix<P::Scalar>, DIGEST_ELEMS>(
                &tcs.hasher,
                tallest_matrices,
            )];
        loop {
            let prev_layer = digest_layers.last().unwrap().as_slice();
            if prev_layer.len() == 1 {
                break;
            }
            let next_layer_len = prev_layer.len() / 2;

            // The matrices that get injected at this layer.
            let matrices_to_inject = leaves_largest_first
                .peeking_take_while(|m| m.height().next_power_of_two() == next_layer_len)
                .copied()
                .collect_vec();

            let next_digests =
                compress_and_inject::<
                    P,
                    PW,
                    GC::Hasher,
                    GC::Compressor,
                    RowMajorMatrix<P::Scalar>,
                    DIGEST_ELEMS,
                >(prev_layer, matrices_to_inject, &tcs.hasher, &tcs.compressor);
            digest_layers.push(next_digests);
        }

        let digests = FieldMerkleTreeDigests { digest_layers: Arc::new(digest_layers) };
        let root = digests.digest_layers.last().unwrap()[0];
        let log_height = height.next_power_of_two().ilog2() as usize;
        let hash: [PW::Value; DIGEST_ELEMS] = tcs.hasher.hash_iter([
            GC::F::from_canonical_usize(log_height),
            GC::F::from_canonical_usize(total_width),
        ]);
        let compressed_root = tcs.compressor.compress([root, hash]);
        Ok((compressed_root.into(), (digests, root.into(), log_height, total_width)))
    }

    fn prove_openings_at_indices(
        &self,
        data: Self::ProverData,
        indices: &[usize],
    ) -> Result<MerkleTreeTcsProof<GC::Digest>, Self::ProverError> {
        let height = data.0.digest_layers.len() - 1;
        let path_storage = indices
            .iter()
            .flat_map(|idx| {
                data.0
                    .digest_layers
                    .iter()
                    .take(height)
                    .enumerate()
                    .map(move |(i, layer)| layer[(idx >> i) ^ 1].into())
            })
            .collect::<Vec<_>>();
        let paths = Tensor::from(path_storage).reshape([indices.len(), height]);
        let proof = MerkleTreeTcsProof {
            log_tensor_height: data.2,
            width: data.3,
            merkle_root: data.1,
            paths,
        };
        Ok(proof)
    }
}

impl<P, PW, GC, const DIGEST_ELEMS: usize> ComputeTcsOpenings<GC, CpuBackend>
    for FieldMerkleTreeProver<P, PW, GC, DIGEST_ELEMS>
where
    GC: IopCtx,
    GC::Digest: Into<[PW::Value; DIGEST_ELEMS]> + From<[PW::Value; DIGEST_ELEMS]>,
    P: PackedField<Scalar = GC::F>,
    PW: PackedValue,
    GC::Hasher: CryptographicHasher<P::Scalar, [PW::Value; DIGEST_ELEMS]>
        + CryptographicHasher<P::Scalar, GC::Digest>,
    GC::Hasher: CryptographicHasher<P, [PW; DIGEST_ELEMS]>,
    GC::Hasher: Sync,
    GC::Compressor: PseudoCompressionFunction<[PW::Value; DIGEST_ELEMS], 2>
        + PseudoCompressionFunction<GC::Digest, 2>,
    GC::Compressor: PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>,
    GC::Compressor: Sync,
    PW::Value: Eq + std::fmt::Debug,
    [PW::Value; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
{
    fn compute_openings_at_indices<T>(
        &self,
        tensors: Message<T>,
        indices: &[usize],
    ) -> Tensor<GC::F, CpuBackend>
    where
        T: OwnedBorrow<Tensor<GC::F, CpuBackend>>,
    {
        let total_width = tensors
            .iter()
            .map(|tensor| {
                let tensor_ref: &T = tensor.borrow();
                let tensor_ref: &Tensor<GC::F, CpuBackend> = tensor_ref.borrow();
                tensor_ref.sizes()[1]
            })
            .sum::<usize>();

        let mut openings = Vec::new();
        for tensor in tensors.iter() {
            let tensor_ref: &T = tensor.borrow();
            let tensor = tensor_ref.borrow();
            let width = tensor.sizes()[1];
            let openings_for_tensor = indices
                .iter()
                .flat_map(|idx| tensor.get(*idx).unwrap().as_slice())
                .cloned()
                .collect::<Vec<_>>();
            let openings_for_tensor =
                RowMajorMatrix::new(openings_for_tensor, width).transpose().values;
            openings.extend(openings_for_tensor);
        }
        Tensor::from(openings).reshape([total_width, indices.len()]).transpose()
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use rand::{thread_rng, Rng};
    use slop_baby_bear::{baby_bear_poseidon2::BabyBearDegree4Duplex, BabyBear};
    use slop_commit::Message;
    use slop_koala_bear::{KoalaBear, KoalaBearDegree4Duplex};
    use slop_tensor::Tensor;

    use crate::MerkleTreeTcs;

    use super::super::{Poseidon2BabyBear16Prover, Poseidon2KoalaBear16Prover};
    use super::*;

    #[test]
    fn test_merkle_proof_sync() {
        let mut rng = thread_rng();

        let height: usize = 1 << 10;
        let width = 25;
        let num_tensors = 10;

        let num_indices = 5;

        let tensors = (0..num_tensors)
            .map(|_| Tensor::<BabyBear>::rand(&mut rng, [height, width]))
            .collect::<Message<_>>();

        let prover = Poseidon2BabyBear16Prover::default();
        let (commitment, data) = prover.commit_tensors(tensors.clone()).unwrap();

        let indices = (0..num_indices).map(|_| rng.gen_range(0..height)).collect_vec();
        let proof = prover.prove_openings_at_indices(data, &indices).unwrap();
        let openings = prover.compute_openings_at_indices(tensors, &indices);

        let tcs = MerkleTreeTcs::<BabyBearDegree4Duplex>::default();
        tcs.verify_tensor_openings(
            &commitment,
            &indices,
            &openings,
            width * num_tensors,
            slop_utils::log2_strict_usize(height),
            &proof,
        )
        .unwrap();
    }

    #[test]
    fn test_kb_merkle_proof_sync() {
        let mut rng = thread_rng();

        let height = 1 << 10;
        let width = 25;
        let num_tensors = 10;

        let num_indices = 5;

        let tensors = (0..num_tensors)
            .map(|_| Tensor::<KoalaBear>::rand(&mut rng, [height, width]))
            .collect::<Message<_>>();

        let prover = Poseidon2KoalaBear16Prover::default();
        let (commitment, data) = prover.commit_tensors(tensors.clone()).unwrap();

        let indices = (0..num_indices).map(|_| rng.gen_range(0..height)).collect_vec();
        let proof = prover.prove_openings_at_indices(data, &indices).unwrap();
        let openings = prover.compute_openings_at_indices(tensors, &indices);

        let tcs = MerkleTreeTcs::<KoalaBearDegree4Duplex>::default();

        tcs.verify_tensor_openings(
            &commitment,
            &indices,
            &openings,
            width * num_tensors,
            slop_utils::log2_strict_usize(height),
            &proof,
        )
        .unwrap();
    }
}
