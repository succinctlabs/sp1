pub mod domain;
// pub mod hints;
pub mod two_adic_pcs;
pub mod types;

pub use domain::*;
use p3_fri::verifier::FriChallenges;
use p3_fri::FriConfig;
use p3_matrix::Dimensions;
use sp1_core::utils::InnerChallengeMmcs;
use sp1_primitives::types::RecursionProgramType;
use sp1_recursion_compiler::ir::ExtensionOperand;
use sp1_recursion_compiler::ir::Ptr;
use sp1_recursion_compiler::ir::SymbolicExt;
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
use crate::challenger::CanSampleVariable;
use crate::challenger::DuplexChallengerVariable;
use crate::challenger::FeltChallenger;

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L27
pub fn verify_shape_and_sample_challenges<C: Config, Mmcs>(
    builder: &mut Builder<C>,
    config: &FriConfig<Mmcs>,
    proof: &FriProofVariable<C>,
    challenger: &mut DuplexChallengerVariable<C>,
) -> FriChallengesVariable<C> {
    let betas: Vec<Ext<C::F, C::EF>> = proof
        .commit_phase_commits
        .clone()
        .into_iter()
        .map(|commitment| {
            challenger.observe_commitment(builder, commitment);
            challenger.sample_ext(builder)
        })
        .collect();

    // Observe the final polynomial.
    for final_poly_felt in builder.ext2felt_circuit(proof.final_poly) {
        challenger.observe(builder, final_poly_felt);
    }

    assert_eq!(proof.query_proofs.len(), config.num_queries);

    challenger.check_witness(builder, config.proof_of_work_bits, proof.pow_witness);

    // let num_commit_phase_commits = proof.commit_phase_commits.len();
    // let log_max_height = num_commit_phase_commits + config.log_blowup;

    let query_indices = (0..config.num_queries)
        .map(|_| challenger.sample(builder))
        .collect::<Vec<_>>();

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
    config: &FriConfig<InnerChallengeMmcs>,
    proof: &FriProofVariable<C>,
    challenges: &FriChallengesVariable<C>,
    reduced_openings: &Vec<Vec<C::EF>>,
) where
    C::F: TwoAdicField,
    C::EF: TwoAdicField,
{
    let nb_commit_phase_commits = proof.commit_phase_commits.len();
    let log_max_height = nb_commit_phase_commits + config.log_blowup;
    for i in 0..challenges.query_indices.len() {
        let index_bits = challenges.query_indices[i];
        let query_proof = proof.query_proofs[i];
        let ro = reduced_openings[i];

        let folded_eval = verify_query(
            builder,
            config,
            proof.commit_phase_commits,
            index_bits,
            query_proof,
            challenges.betas,
            ro,
            log_max_height,
        );

        builder.assert_ext_eq(folded_eval, proof.final_poly);
    }
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
    config: &FriConfig<InnerChallengeMmcs>,
    commit_phase_commits: Vec<DigestVariable<C>>,
    index_bits: Vec<Felt<<C as Config>::F>>,
    proof: FriQueryProofVariable<C>,
    betas: Vec<Ext<C::F, C::EF>>,
    reduced_openings: Vec<Ext<C::F, C::EF>>,
    log_max_height: usize,
) -> Ext<C::F, C::EF> {
    let mut folded_eval: Ext<C::F, C::EF> = builder.eval(SymbolicExt::from_f(C::EF::zero()));
    // let two_adic_generator = builder.eval(SymbolicExt::from_f(C::EF::two_adic_generator(
    //     log_max_height,
    // )));
    // let index_bits = builder.num2bits_v_circuit(index, 32);
    // let rev_reduced_index = builder.reverse_bits_len_circuit(index_bits.clone(), log_max_height);
    // let mut x = builder.exp_e_bits(two_adic_generator, rev_reduced_index);

    let mut offset = 0;
    for (((log_folded_height, commit), step), beta) in
    (0..log_max_height).rev().zip(
        commit_phase_commits).zip(
        &proof.commit_phase_openings).zip(
        betas) 
     {
    //     folded_eval = builder.eval(folded_eval + reduced_openings[log_folded_height + 1]);

    //     let one: Var<_> = builder.eval(C::N::one());
    //     let index_sibling: Var<_> = builder.eval(one - index_bits.clone()[offset]);
    //     let index_pair = &index_bits[(offset + 1)..];

    //     let evals_ext = [
    //         builder.select_ef(index_sibling, folded_eval, step.sibling_value),
    //         builder.select_ef(index_sibling, step.sibling_value, folded_eval),
    //     ];
    //     let evals_felt = vec![
    //         builder.ext2felt_circuit(evals_ext[0]).to_vec(),
    //         builder.ext2felt_circuit(evals_ext[1]).to_vec(),
    //     ];

    //     let dims = &[Dimensions {
    //         width: 2,
    //         height: (1 << log_folded_height),
    //     }];
    //     verify_batch::<C, 4>(
    //         builder,
    //         commit,
    //         dims.to_vec(),
    //         index_pair.to_vec(),
    //         [evals_felt].to_vec(),
    //         step.opening_proof.clone(),
    //     );

    //     let xs_new = builder.eval(x * C::EF::two_adic_generator(1));
    //     let xs = [
    //         builder.select_ef(index_sibling, x, xs_new),
    //         builder.select_ef(index_sibling, xs_new, x),
    //     ];
    //     folded_eval = builder
    //         .eval(evals_ext[0] + (beta - xs[0]) * (evals_ext[1] - evals_ext[0]) / (xs[1] - xs[0]));
    //     x = builder.eval(x * x);
    //     offset += 1;
    }

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
    dimensions: Vec<Dimensions>,
    index_bits: Vec<Felt<C::F>>,
    opened_values: Vec<C::EF>,
    proof: &Vec<DigestVariable<C>>,
) {
    builder.cycle_tracker("verify-batch");
    // The index of which table to process next.
    let index: Var<C::N> = builder.eval(C::N::zero());

    // The height of the current layer (padded).
    let current_height = dimensions[index].height;

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
        let bit = index_bits[i];

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
            let next_height = dimensions[index].height;
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
        let e1 = commit[i];
        let e2 = root[i];
        builder.assert_felt_eq(e1, e2);
    }
    builder.cycle_tracker("verify-batch");
}

#[allow(clippy::type_complexity)]
pub fn reduce_fast<C: Config, const D: usize>(
    builder: &mut Builder<C>,
    dim_idx: Var<C::N>,
    dims: &Vec<DimensionsVariable<C>>,
    curr_height_padded: Var<C::N>,
    opened_values: &Vec<C::EF>,
) -> Vec<Felt<C::F>> {
    builder.cycle_tracker("verify-batch-reduce-fast");
    let nb_opened_values: Var<_> = builder.eval(C::N::zero());
    let mut nested_opened_values: Vec<_>>> = builder.dyn_array(8192);
    let start_dim_idx: Var<_> = builder.eval(dim_idx);
    builder.cycle_tracker("verify-batch-reduce-fast-setup");
    builder
        .range(start_dim_idx, dims.len())
        .for_each(|i, builder| {
            let height = dims[i].height;
            builder.if_eq(height, curr_height_padded).then(|builder| {
                let opened_values = opened_values[i];
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
