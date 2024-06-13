pub mod domain;
pub mod hints;
pub mod two_adic_pcs;
pub mod types;

pub use domain::*;
use sp1_recursion_compiler::ir::ExtensionOperand;
use sp1_recursion_compiler::ir::Ptr;
use sp1_recursion_core::runtime::DIGEST_SIZE;
pub use two_adic_pcs::*;

use p3_field::AbstractField;
use p3_field::Field;
use p3_field::TwoAdicField;

use sp1_recursion_compiler::ir::Array;
use sp1_recursion_compiler::ir::Builder;
use sp1_recursion_compiler::ir::Config;
use sp1_recursion_compiler::ir::Ext;
use sp1_recursion_compiler::ir::Felt;
use sp1_recursion_compiler::ir::SymbolicVar;
use sp1_recursion_compiler::ir::Usize;
use sp1_recursion_compiler::ir::Var;

use self::types::DigestVariable;
use self::types::DimensionsVariable;
use self::types::FriChallengesVariable;
use self::types::FriConfigVariable;
use self::types::FriProofVariable;
use self::types::FriQueryProofVariable;
use crate::challenger::CanObserveVariable;
use crate::challenger::CanSampleBitsVariable;
use crate::challenger::DuplexChallengerVariable;
use crate::challenger::FeltChallenger;

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L27
pub fn verify_shape_and_sample_challenges<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfigVariable<C>,
    proof: &FriProofVariable<C>,
    challenger: &mut DuplexChallengerVariable<C>,
) -> FriChallengesVariable<C> {
    let mut betas: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(proof.commit_phase_commits.len());

    builder
        .range(0, proof.commit_phase_commits.len())
        .for_each(|i, builder| {
            let comm = builder.get(&proof.commit_phase_commits, i);
            challenger.observe(builder, comm);
            let sample = challenger.sample_ext(builder);
            builder.set(&mut betas, i, sample);
        });

    let num_query_proofs = proof.query_proofs.len().materialize(builder);
    builder
        .if_ne(num_query_proofs, config.num_queries)
        .then(|builder| {
            builder.error();
        });

    challenger.check_witness(builder, config.proof_of_work_bits, proof.pow_witness);

    let num_commit_phase_commits = proof.commit_phase_commits.len().materialize(builder);
    let log_max_height: Var<_> = builder.eval(num_commit_phase_commits + config.log_blowup);
    let mut query_indices = builder.array(config.num_queries);
    builder.range(0, config.num_queries).for_each(|i, builder| {
        let index_bits = challenger.sample_bits(builder, Usize::Var(log_max_height));
        builder.set(&mut query_indices, i, index_bits);
    });

    FriChallengesVariable {
        query_indices,
        betas,
    }
}

/// Verifies a set of FRI challenges.
///
/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L67
#[allow(clippy::type_complexity)]
pub fn verify_challenges<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfigVariable<C>,
    proof: &FriProofVariable<C>,
    challenges: &FriChallengesVariable<C>,
    reduced_openings: &Array<C, Array<C, Ext<C::F, C::EF>>>,
) where
    C::F: TwoAdicField,
    C::EF: TwoAdicField,
{
    let nb_commit_phase_commits = proof.commit_phase_commits.len().materialize(builder);
    let log_max_height = builder.eval(nb_commit_phase_commits + config.log_blowup);
    builder
        .range(0, challenges.query_indices.len())
        .for_each(|i, builder| {
            let index_bits = builder.get(&challenges.query_indices, i);
            let query_proof = builder.get(&proof.query_proofs, i);
            let ro = builder.get(reduced_openings, i);

            let folded_eval = verify_query(
                builder,
                config,
                &proof.commit_phase_commits,
                &index_bits,
                &query_proof,
                &challenges.betas,
                &ro,
                Usize::Var(log_max_height),
            );

            builder.assert_ext_eq(folded_eval, proof.final_poly);
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
    config: &FriConfigVariable<C>,
    commit_phase_commits: &Array<C, DigestVariable<C>>,
    index_bits: &Array<C, Var<C::N>>,
    proof: &FriQueryProofVariable<C>,
    betas: &Array<C, Ext<C::F, C::EF>>,
    reduced_openings: &Array<C, Ext<C::F, C::EF>>,
    log_max_height: Usize<C::N>,
) -> Ext<C::F, C::EF>
where
    C::F: TwoAdicField,
    C::EF: TwoAdicField,
{
    builder.cycle_tracker("verify-query");
    let folded_eval: Ext<C::F, C::EF> = builder.eval(C::F::zero());
    let two_adic_generator_f = config.get_two_adic_generator(builder, log_max_height);

    let x = builder.exp_reverse_bits_len_fast(two_adic_generator_f, index_bits, log_max_height);

    let log_max_height = log_max_height.materialize(builder);
    builder
        .range(0, commit_phase_commits.len())
        .for_each(|i, builder| {
            let log_folded_height: Var<_> = builder.eval(log_max_height - i - C::N::one());
            let log_folded_height_plus_one: Var<_> = builder.eval(log_folded_height + C::N::one());
            let commit = builder.get(commit_phase_commits, i);
            let step = builder.get(&proof.commit_phase_openings, i);
            let beta = builder.get(betas, i);

            let reduced_opening = builder.get(reduced_openings, log_folded_height_plus_one);
            builder.assign(folded_eval, folded_eval + reduced_opening);

            let index_bit = builder.get(index_bits, i);
            let index_sibling_mod_2: Var<C::N> =
                builder.eval(SymbolicVar::from(C::N::one()) - index_bit);
            let i_plus_one = builder.eval(i + C::N::one());
            let index_pair = index_bits.shift(builder, i_plus_one);

            let mut evals: Array<C, Ext<C::F, C::EF>> = builder.array(2);
            builder.set_value(&mut evals, 0, folded_eval);
            builder.set_value(&mut evals, 1, folded_eval);
            builder.set_value(&mut evals, index_sibling_mod_2, step.sibling_value);

            let dims = DimensionsVariable::<C> {
                height: builder.sll(C::N::one(), Usize::Var(log_folded_height)),
            };
            let mut dims_slice: Array<C, DimensionsVariable<C>> = builder.array(1);
            builder.set_value(&mut dims_slice, 0, dims);

            let mut opened_values = builder.array(1);
            builder.set_value(&mut opened_values, 0, evals.clone());
            verify_batch::<C, 4>(
                builder,
                &commit,
                dims_slice,
                index_pair,
                opened_values,
                &step.opening_proof,
            );

            let two_adic_generator_one = config.get_two_adic_generator(builder, Usize::Const(1));
            let xs_0: Ext<_, _> = builder.eval(x);
            let xs_1: Ext<_, _> = builder.eval(x);
            builder
                .if_eq(index_sibling_mod_2, C::N::zero())
                .then_or_else(
                    |builder| {
                        builder.assign(xs_0, x * two_adic_generator_one.to_operand().symbolic());
                    },
                    |builder| {
                        builder.assign(xs_1, x * two_adic_generator_one.to_operand().symbolic());
                    },
                );

            let eval_0 = builder.get(&evals, 0);
            let eval_1 = builder.get(&evals, 1);
            builder.assign(
                folded_eval,
                eval_0 + (beta - xs_0) * (eval_1 - eval_0) / (xs_1 - xs_0),
            );

            builder.assign(x, x * x);
        });

    builder.cycle_tracker("verify-query");
    folded_eval
}

/// Verifies a batch opening.
///
/// Assumes the dimensions have already been sorted by tallest first.
///
/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/merkle-tree/src/mmcs.rs#L92
#[allow(clippy::type_complexity)]
#[allow(unused_variables)]
pub fn verify_batch<C: Config, const D: usize>(
    builder: &mut Builder<C>,
    commit: &DigestVariable<C>,
    dimensions: Array<C, DimensionsVariable<C>>,
    index_bits: Array<C, Var<C::N>>,
    opened_values: Array<C, Array<C, Ext<C::F, C::EF>>>,
    proof: &Array<C, DigestVariable<C>>,
) {
    builder.cycle_tracker("verify-batch");
    // The index of which table to process next.
    let index: Var<C::N> = builder.eval(C::N::zero());

    // The height of the current layer (padded).
    let current_height = builder.get(&dimensions, index).height;

    // Reduce all the tables that have the same height to a single root.
    let root = reduce_fast::<C, D>(builder, index, &dimensions, current_height, &opened_values);
    let root_ptr = match root {
        Array::Fixed(_) => panic!("root is fixed"),
        Array::Dyn(ptr, _) => ptr,
    };

    // For each sibling in the proof, reconstruct the root.
    let one: Var<_> = builder.eval(C::N::one());
    let left: Ptr<C::N> = builder.uninit();
    let right: Ptr<C::N> = builder.uninit();
    builder.range(0, proof.len()).for_each(|i, builder| {
        let sibling = builder.get_ptr(proof, i);
        let bit = builder.get(&index_bits, i);

        builder.if_eq(bit, C::N::one()).then_or_else(
            |builder| {
                builder.assign(left, sibling);
                builder.assign(right, root_ptr);
            },
            |builder| {
                builder.assign(left, root_ptr);
                builder.assign(right, sibling);
            },
        );

        builder.poseidon2_compress_x(
            &mut Array::Dyn(root_ptr, Usize::Const(0)),
            &Array::Dyn(left, Usize::Const(0)),
            &Array::Dyn(right, Usize::Const(0)),
        );
        builder.assign(current_height, current_height * (C::N::two().inverse()));

        builder.if_ne(index, dimensions.len()).then(|builder| {
            let next_height = builder.get(&dimensions, index).height;
            builder.if_eq(next_height, current_height).then(|builder| {
                let next_height_openings_digest = reduce_fast::<C, D>(
                    builder,
                    index,
                    &dimensions,
                    current_height,
                    &opened_values,
                );
                builder.poseidon2_compress_x(
                    &mut root.clone(),
                    &root.clone(),
                    &next_height_openings_digest,
                );
            });
        })
    });

    // Assert that the commitments match.
    for i in 0..DIGEST_SIZE {
        let e1 = builder.get(commit, i);
        let e2 = builder.get(&root, i);
        builder.assert_felt_eq(e1, e2);
    }
    builder.cycle_tracker("verify-batch");
}

#[allow(clippy::type_complexity)]
pub fn reduce_fast<C: Config, const D: usize>(
    builder: &mut Builder<C>,
    dim_idx: Var<C::N>,
    dims: &Array<C, DimensionsVariable<C>>,
    curr_height_padded: Var<C::N>,
    opened_values: &Array<C, Array<C, Ext<C::F, C::EF>>>,
) -> Array<C, Felt<C::F>> {
    builder.cycle_tracker("verify-batch-reduce-fast");
    let nb_opened_values: Var<_> = builder.eval(C::N::zero());
    let mut nested_opened_values: Array<_, Array<_, Ext<_, _>>> = builder.dyn_array(8192);
    let start_dim_idx: Var<_> = builder.eval(dim_idx);
    builder.cycle_tracker("verify-batch-reduce-fast-setup");
    builder
        .range(start_dim_idx, dims.len())
        .for_each(|i, builder| {
            let height = builder.get(dims, i).height;
            builder.if_eq(height, curr_height_padded).then(|builder| {
                let opened_values = builder.get(opened_values, i);
                builder.set_value(
                    &mut nested_opened_values,
                    nb_opened_values,
                    opened_values.clone(),
                );
                builder.assign(nb_opened_values, nb_opened_values + C::N::one());
                builder.assign(dim_idx, dim_idx + C::N::one());
            });
        });
    builder.cycle_tracker("verify-batch-reduce-fast-setup");

    let h = if D == 1 {
        let nested_opened_values = match nested_opened_values {
            Array::Dyn(ptr, len) => Array::Dyn(ptr, len),
            _ => unreachable!(),
        };
        nested_opened_values.truncate(builder, Usize::Var(nb_opened_values));
        builder.poseidon2_hash_x(&nested_opened_values)
    } else {
        nested_opened_values.truncate(builder, Usize::Var(nb_opened_values));
        builder.poseidon2_hash_ext(&nested_opened_values)
    };
    builder.cycle_tracker("verify-batch-reduce-fast");
    h
}
