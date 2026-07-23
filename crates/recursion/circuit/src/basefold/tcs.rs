use crate::{
    basefold::merkle_tree::{verify, verify_batch8},
    hash::FieldHasherVariable,
    CircuitConfig,
};
use itertools::Itertools;
use slop_algebra::AbstractField;
use slop_tensor::Tensor;
use sp1_primitives::SP1Field;
use sp1_recursion_compiler::ir::{Builder, Felt, IrIter};
use std::marker::PhantomData;

/// An opening of a tensor commitment scheme.
pub struct RecursiveTensorCsOpening<CommitmentVariable> {
    /// The claimed values of the opening.
    pub values: Tensor<Felt<SP1Field>>,
    /// The proof of the opening.
    pub proof: Tensor<CommitmentVariable>,

    pub merkle_root: CommitmentVariable,

    pub log_height: usize,
    pub width: usize,
}

#[derive(Debug, Copy, PartialEq, Eq)]
pub struct RecursiveMerkleTreeTcs<C, M>(pub PhantomData<(C, M)>);

impl<C, M> Clone for RecursiveMerkleTreeTcs<C, M> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<C, M> RecursiveMerkleTreeTcs<C, M>
where
    C: CircuitConfig,
    M: FieldHasherVariable<C>,
{
    pub fn verify_tensor_openings(
        builder: &mut Builder<C>,
        commit: &M::DigestVariable,
        indices: &[Vec<C::Bit>],
        opening: &RecursiveTensorCsOpening<M::DigestVariable>,
    ) {
        let chunk_size = indices.len().div_ceil(8);

        let log_height = builder.constant(SP1Field::from_canonical_usize(opening.log_height));
        let width = builder.constant(SP1Field::from_canonical_usize(opening.width));
        let hash = M::hash(builder, &[log_height, width]);
        let expected_commit = M::compress(builder, [opening.merkle_root, hash]);
        M::assert_digest_eq(builder, expected_commit, *commit);

        indices
            .iter()
            .zip_eq(opening.proof.split())
            .map(|(x, y)| (x.clone(), y.as_slice().to_vec()))
            .collect::<Vec<_>>()
            .chunks(chunk_size)
            .enumerate()
            .ir_par_map_collect::<Vec<_>, _, _>(builder, |builder, (i, chunk)| {
                // Verify the chunk's queries in groups of 8, hashing the opened rows and
                // walking the Merkle paths in lockstep so the Poseidon2 permutations form
                // independent 8-lane batches. The remainder uses the scalar path.
                let mut group_start = 0;
                while chunk.len() - group_start >= 8 {
                    let values: [Vec<Felt<SP1Field>>; 8] = core::array::from_fn(|lane| {
                        opening
                            .values
                            .get(i * chunk_size + group_start + lane)
                            .unwrap()
                            .as_slice()
                            .to_vec()
                    });
                    let digests = M::hash_batch8(builder, &values);
                    let paths = core::array::from_fn(|lane| chunk[group_start + lane].1.clone());
                    let index_bits =
                        core::array::from_fn(|lane| chunk[group_start + lane].0.clone());
                    verify_batch8::<C, M>(builder, paths, index_bits, digests, opening.merkle_root);
                    group_start += 8;
                }
                for (j, (index, path)) in chunk.iter().enumerate().skip(group_start) {
                    let claimed_values_slices =
                        opening.values.get(i * chunk_size + j).unwrap().as_slice().to_vec();

                    let path = path.as_slice().to_vec();
                    let digest = M::hash(builder, &claimed_values_slices);

                    verify::<C, M>(builder, path, index.to_vec(), digest, opening.merkle_root);
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};
    use slop_commit::Message;
    use slop_merkle_tree::{ComputeTcsOpenings, MerkleTreeOpeningAndProof, TensorCsProver};
    use sp1_hypercube::inner_perm;
    use sp1_recursion_compiler::circuit::AsmConfig;
    use std::sync::Arc;

    use slop_algebra::extension::BinomialExtensionField;
    use sp1_primitives::{SP1DiffusionMatrix, SP1GlobalContext};

    use crate::witness::Witnessable;

    use super::*;
    use itertools::Itertools;
    use slop_tensor::Tensor;
    use sp1_hypercube::prover::SP1MerkleTreeProver;
    use sp1_recursion_compiler::circuit::{AsmBuilder, AsmCompiler};
    use sp1_recursion_executor::Executor;

    use sp1_primitives::SP1Field;
    type F = SP1Field;
    type EF = BinomialExtensionField<SP1Field, 4>;

    #[test]
    fn test_merkle_proof() {
        let mut rng = thread_rng();

        let height = rng.gen_range(500..2000);
        let width = rng.gen_range(15..30);
        let num_tensors = rng.gen_range(5..15);

        let num_indices = rng.gen_range(2..10);

        let tensors = (0..num_tensors)
            .map(|_| Tensor::<SP1Field>::rand(&mut rng, [height, width]))
            .collect::<Message<_>>();

        let prover = SP1MerkleTreeProver::default();
        let (root, data) = prover.commit_tensors(tensors.clone()).unwrap();

        let indices = (0..num_indices).map(|_| rng.gen_range(0..height)).collect_vec();
        let proof = prover.prove_openings_at_indices(data, &indices).unwrap();
        let openings = prover.compute_openings_at_indices(tensors, &indices);
        let opening: MerkleTreeOpeningAndProof<SP1GlobalContext> =
            MerkleTreeOpeningAndProof { values: openings, proof };

        let bit_len = height.next_power_of_two().ilog2();

        let mut builder = AsmBuilder::default();
        let mut witness_stream = Vec::new();

        let mut index_bits = Vec::new();
        for index in indices {
            let bits = (0..bit_len).map(|i| (index >> i) & 1 == 1).collect_vec();
            Witnessable::<AsmConfig>::write(&bits, &mut witness_stream);
            let bits = bits.read(&mut builder);
            index_bits.push(bits);
        }

        Witnessable::<AsmConfig>::write(&root, &mut witness_stream);
        let root = root.read(&mut builder);
        Witnessable::<AsmConfig>::write(&opening, &mut witness_stream);
        let opening = opening.read(&mut builder);

        RecursiveMerkleTreeTcs::<AsmConfig, SP1GlobalContext>::verify_tensor_openings(
            &mut builder,
            &root,
            &index_bits,
            &opening,
        );

        let block = builder.into_root_block();
        let mut compiler = AsmCompiler::default();
        let program = Arc::new(compiler.compile_inner(block).validate().unwrap());
        let mut executor =
            Executor::<F, EF, SP1DiffusionMatrix>::new(program.clone(), inner_perm());
        executor.witness_stream = witness_stream.into();
        executor.run().unwrap();
    }

    #[test]
    fn test_invalid_merkle_proof() {
        let mut rng = thread_rng();

        let height = rng.gen_range(500..2000);
        let width = rng.gen_range(15..30);
        let num_tensors = rng.gen_range(5..15);

        let num_indices = rng.gen_range(2..10);

        let tensors = (0..num_tensors)
            .map(|_| Tensor::<SP1Field>::rand(&mut rng, [height, width]))
            .collect::<Message<_>>();

        let prover = SP1MerkleTreeProver::default();
        let (root, data) = prover.commit_tensors(tensors.clone()).unwrap();

        let indices = (0..num_indices).map(|_| rng.gen_range(0..height)).collect_vec();
        let proof = prover.prove_openings_at_indices(data, &indices).unwrap();
        let openings = prover.compute_openings_at_indices(tensors, &indices);
        let opening: MerkleTreeOpeningAndProof<SP1GlobalContext> =
            MerkleTreeOpeningAndProof { values: openings, proof };

        let bit_len = height.next_power_of_two().ilog2();

        let mut builder = AsmBuilder::default();
        let mut witness_stream = Vec::new();

        let mut index_bits = Vec::new();
        for index in indices {
            let bits = (0..bit_len)
                .map(|i| if i == 0 { (index >> i) & 1 == 0 } else { (index >> i) & 1 == 1 })
                .collect_vec();
            Witnessable::<AsmConfig>::write(&bits, &mut witness_stream);
            let bits = bits.read(&mut builder);
            index_bits.push(bits);
        }

        Witnessable::<AsmConfig>::write(&root, &mut witness_stream);
        let root = root.read(&mut builder);
        Witnessable::<AsmConfig>::write(&opening, &mut witness_stream);
        let opening = opening.read(&mut builder);

        RecursiveMerkleTreeTcs::<AsmConfig, SP1GlobalContext>::verify_tensor_openings(
            &mut builder,
            &root,
            &index_bits,
            &opening,
        );

        let block = builder.into_root_block();
        let mut compiler = AsmCompiler::default();
        let program = Arc::new(compiler.compile_inner(block).validate().unwrap());
        let mut executor =
            Executor::<F, EF, SP1DiffusionMatrix>::new(program.clone(), inner_perm());
        executor.witness_stream = witness_stream.into();
        executor.run().expect_err("merkle proof should not verify");
    }
}
