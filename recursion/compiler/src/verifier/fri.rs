use super::challenger::DuplexChallenger;
use super::types::Dimensions;
use super::types::FriChallenges;
use super::types::FriConfig;
use super::types::FriProof;
use super::types::FriQueryProof;
use super::types::DIGEST_SIZE;
use super::types::PERMUTATION_WIDTH;
use crate::prelude::Array;
use crate::prelude::Builder;
use crate::prelude::Config;
use crate::prelude::DslIR;
use crate::prelude::Felt;
use crate::prelude::Usize;
use crate::prelude::Var;
use crate::verifier::types::Commitment;

use p3_field::AbstractField;
use p3_field::TwoAdicField;

impl<C: Config> Builder<C> {
    /// Converts a usize to a fixed length of bits.
    pub fn num2bits_v(&mut self, num: Usize<C::N>) -> Array<C, Var<C::N>> {
        let output = self.array::<Var<_>, _>(Usize::Const(29));
        self.operations.push(DslIR::Num2BitsV(output.clone(), num));
        output
    }

    /// Converts a felt to a fixed length of bits.
    pub fn num2bits_f(&mut self, num: Felt<C::F>) -> Array<C, Var<C::N>> {
        let output = self.array::<Var<_>, _>(Usize::Const(29));
        self.operations.push(DslIR::Num2BitsF(output.clone(), num));
        output
    }

    /// Applies the Poseidon2 permutation to the given array.
    ///
    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/poseidon2/src/lib.rs#L119
    pub fn poseidon2_permute(&mut self, array: &Array<C, Felt<C::F>>) -> Array<C, Felt<C::F>> {
        let output = match array {
            Array::Fixed(values) => {
                assert_eq!(values.len(), PERMUTATION_WIDTH);
                self.array::<Felt<C::F>, _>(Usize::Const(PERMUTATION_WIDTH))
            }
            Array::Dyn(_, len) => self.array::<Felt<C::F>, _>(*len),
        };
        self.operations
            .push(DslIR::Poseidon2Permute(output.clone(), array.clone()));
        output
    }

    /// Applies the Poseidon2 compression function to the given array.
    ///
    /// Assumes we are doing a 2-1 compression function with 8 element chunks.
    ///
    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/symmetric/src/compression.rs#L35
    pub fn poseidon2_compress(
        &mut self,
        left: &Array<C, Felt<C::F>>,
        right: &Array<C, Felt<C::F>>,
    ) -> Array<C, Felt<C::F>> {
        let output = match left {
            Array::Fixed(values) => {
                assert_eq!(values.len(), DIGEST_SIZE);
                self.array::<Felt<C::F>, _>(Usize::Const(DIGEST_SIZE))
            }
            Array::Dyn(_, _) => {
                let len: Var<C::N> = self.eval(C::N::from_canonical_usize(DIGEST_SIZE));
                self.array::<Felt<C::F>, _>(Usize::Var(len))
            }
        };
        self.operations.push(DslIR::Poseidon2Compress(
            output.clone(),
            left.clone(),
            right.clone(),
        ));
        output
    }

    /// Applies the Poseidon2 hash function to the given array using a padding-free sponge.
    ///
    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/symmetric/src/sponge.rs#L32
    pub fn poseidon2_hash(&mut self, input: Array<C, Felt<C::F>>) -> Array<C, Felt<C::F>> {
        let len = match input {
            Array::Fixed(_) => Usize::Const(PERMUTATION_WIDTH),
            Array::Dyn(_, _) => {
                let len: Var<_> = self.eval(C::N::from_canonical_usize(PERMUTATION_WIDTH));
                Usize::Var(len)
            }
        };
        let state = self.array::<Felt<C::F>, _>(len);
        let start: Usize<C::N> = Usize::Const(0);
        let end = len;
        self.range(start, end).for_each(|_, builder| {
            let new_state = builder.poseidon2_permute(&state);
            builder.assign(state.clone(), new_state);
        });
        state
    }

    /// Materializes a usize into a variable.
    pub fn materialize(&mut self, num: Usize<C::N>) -> Var<C::N> {
        match num {
            Usize::Const(num) => self.eval(C::N::from_canonical_usize(num)),
            Usize::Var(num) => num,
        }
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/baby-bear/src/baby_bear.rs#L306
    pub fn generator(&mut self) -> Felt<C::F> {
        self.eval(C::F::from_canonical_u32(0x78000000))
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/baby-bear/src/baby_bear.rs#L302
    #[allow(unused_variables)]
    pub fn two_adic_generator(&mut self, bits: Usize<C::N>) -> Felt<C::F> {
        let result = self.uninit();
        self.operations.push(DslIR::TwoAdicGenerator(result, bits));
        result
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/util/src/lib.rs#L59
    #[allow(unused_variables)]
    pub fn reverse_bits_len(&mut self, index: Usize<C::N>, bit_len: Usize<C::N>) -> Usize<C::N> {
        let result = self.uninit();
        self.operations
            .push(DslIR::ReverseBitsLen(result, index, bit_len));
        result
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/field/src/field.rs#L79
    #[allow(unused_variables)]
    pub fn exp_usize(&mut self, x: Felt<C::F>, power: Usize<C::N>) -> Felt<C::F> {
        let result = self.uninit();
        self.operations.push(DslIR::ExpUsize(result, x, power));
        result
    }
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L27
#[allow(unused_variables)]
pub fn verify_shape_and_sample_challenges<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig,
    proof: &FriProof<C>,
    challenger: &mut DuplexChallenger<C>,
) -> FriChallenges<C> {
    // let mut challenger = DuplexChallenger::<C> {
    //     nb_inputs: builder.eval(C::N::zero()),
    //     nb_outputs: builder.eval(C::N::zero()),
    //     sponge_state: builder.array(Usize::Const(PERMUTATION_WIDTH)),
    //     input_buffer: builder.array(Usize::Const(PERMUTATION_WIDTH)),
    //     output_buffer: builder.array(Usize::Const(PERMUTATION_WIDTH)),
    // };

    let mut betas: Array<C, Felt<C::F>> = builder.array(proof.commit_phase_commits.len());
    let start = Usize::Const(0);
    let end = proof.commit_phase_commits.len();
    builder.range(start, end).for_each(|i, builder| {
        let comm = builder.get(&proof.commit_phase_commits, i);
        challenger.observe_commitment(builder, comm);
        let sample = challenger.sample(builder);
        builder.set(&mut betas, i, sample);
    });

    let a = builder.materialize(proof.commit_phase_commits.len());
    let b = builder.materialize(Usize::Const(config.num_queries));
    builder.if_ne(a, b).then(|builder| {
        // TODO: throw error
    });

    // TODO: Check PoW.

    let commit_phase_commits_len = builder.materialize(proof.commit_phase_commits.len());
    let log_max_height: Var<_> =
        builder.eval(commit_phase_commits_len + C::N::from_canonical_usize(config.log_blowup));

    let mut query_indices = builder.array::<Var<_>, _>(Usize::Const(config.num_queries));
    let start = Usize::Const(0);
    let end = Usize::Const(config.num_queries);
    builder.range(start, end).for_each(|i, builder| {
        let index = challenger.sample_bits(builder, Usize::Var(log_max_height));
        builder.set(&mut query_indices, i, index);
    });

    FriChallenges {
        query_indices,
        betas,
    }
}

/// Verifies a set of FRI challenges.
///
/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L67
#[allow(unused_variables)]
pub fn verify_challenges<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig,
    proof: &FriProof<C>,
    challenges: &FriChallenges<C>,
    reduced_openings: &Array<C, Array<C, Felt<C::F>>>,
) where
    C::F: TwoAdicField,
{
    let commit_phase_commits_len = builder.materialize(proof.commit_phase_commits.len());
    let log_max_height: Var<_> =
        builder.eval(commit_phase_commits_len + C::N::from_canonical_usize(config.log_blowup));
    let start = Usize::Const(0);
    let end = challenges.query_indices.len();
    builder.range(start, end).for_each(|i, builder| {
        let index = builder.get(&challenges.query_indices, i);
        let query_proof = builder.get(&proof.query_proofs, i);
        let ro = builder.get(reduced_openings, i);
        let folded_eval = verify_query(
            builder,
            config,
            &proof.commit_phase_commits,
            0, // TODO: FIX
            &query_proof,
            &challenges.betas,
            &ro,
            Usize::Var(log_max_height),
        );
        builder.assert_felt_eq(folded_eval, proof.final_poly);
    });
}

/// Verifies a FRI query.
///
/// Currently assumes the index that is accessed is constant.
///
/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L101
#[allow(clippy::too_many_arguments)]
#[allow(unused_variables)]
pub fn verify_query<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig,
    commit_phase_commits: &Array<C, Commitment<C>>,
    mut index: usize,
    proof: &FriQueryProof<C>,
    betas: &Array<C, Felt<C::F>>,
    reduced_openings: &Array<C, Felt<C::F>>,
    log_max_height: Usize<C::N>,
) -> Felt<C::F>
where
    C::F: TwoAdicField,
{
    let folded_eval: Felt<_> = builder.eval(C::F::zero());
    let two_adic_generator = builder.two_adic_generator(log_max_height);
    let power = builder.reverse_bits_len(Usize::Const(index), log_max_height);
    let x = builder.exp_usize(two_adic_generator, power);

    let start = Usize::Const(0);
    let end = log_max_height;
    let end_var = builder.materialize(end);
    builder.range(start, end).for_each(|i, builder| {
        let log_folded_height: Var<_> = builder.eval(end_var - i);
        let reduced_opening_term = builder.get(reduced_openings, log_folded_height);
        builder.assign(folded_eval, folded_eval + reduced_opening_term);

        let index_sibling = index ^ 1;
        let index_pair = index >> 1;

        let step = builder.get(&proof.commit_phase_openings, i);
        let mut evals = [folded_eval; 2];
        evals[index_sibling % 2] = step.sibling_value;

        let commit = builder.get(commit_phase_commits, i);
        let dims = Dimensions::<C> {
            width: 2,
            height: Usize::Var(log_folded_height),
        };
        verify_batch(builder, &commit, &[dims], index, evals, &step.opening_proof);

        let beta = builder.get(betas, i);
        let xs = [x; 2];
        let generator = builder.generator();
        builder.assign(xs[index_sibling % 2], xs[index_sibling % 2] * generator);
        builder.assign(
            folded_eval,
            evals[0] + (beta - xs[0]) * (evals[1] - evals[0]) / (xs[1] - xs[0]),
        );

        index = index_pair;
        builder.assign(x, x * x);
    });

    folded_eval
}

/// Verifies a batch opening.
///
/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/merkle-tree/src/mmcs.rs#L92
#[allow(unused_variables)]
pub fn verify_batch<C: Config>(
    builder: &mut Builder<C>,
    commit: &Commitment<C>,
    dims: &[Dimensions<C>],
    index: usize,
    opened_values: [Felt<C::F>; 2],
    proof: &Array<C, Commitment<C>>,
) {
    let height: Var<_> = builder.materialize(dims[0].height);
    let curr_height_padded: Var<C::N> = builder.eval(height * C::N::from_canonical_usize(2));

    let two: Var<_> = builder.eval(C::N::from_canonical_u32(2));
    let array = builder.array::<Felt<_>, _>(Usize::Var(two));
    let root = builder.poseidon2_hash(array);

    let start = Usize::Const(0);
    let end = proof.len();
    let index_bits = builder.num2bits_v(Usize::Const(index));
    builder.range(start, end).for_each(|i, builder| {
        let bit = builder.get(&index_bits, i);
        let left: Array<C, Felt<C::F>> = builder.uninit();
        let right: Array<C, Felt<C::F>> = builder.uninit();
        let one: Var<_> = builder.eval(C::N::one());
        let sibling = builder.get(proof, i);
        builder.if_eq(bit, one).then_or_else(
            |builder| {
                builder.assign(left.clone(), root.clone());
                builder.assign(right.clone(), sibling.clone());
            },
            |builder| {
                builder.assign(left.clone(), sibling.clone());
                builder.assign(right.clone(), root.clone());
            },
        );

        let new_root = builder.poseidon2_compress(&left, &right);
        builder.assign(root.clone(), new_root);
    });

    let start = Usize::Const(0);
    let end = Usize::Const(DIGEST_SIZE);
    builder.range(start, end).for_each(|i, builder| {
        let lhs = builder.get(commit, i);
        let rhs = builder.get(&root, i);
        builder.assert_felt_eq(lhs, rhs);
    })
}
