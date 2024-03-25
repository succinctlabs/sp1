use p3_field::AbstractField;
use p3_field::TwoAdicField;
use sp1_recursion_derive::DslVariable;

use super::types::Dimensions;
use super::types::{Commitment, FriConfigVariable, FriProofVariable};
use crate::prelude::Felt;
use crate::prelude::MemVariable;
use crate::prelude::Ptr;
use crate::prelude::SymbolicExt;
use crate::prelude::Var;
use crate::prelude::Variable;
use crate::prelude::{Array, Builder, Config, Ext, Usize};
use crate::verifier::fri;
use crate::verifier::fri::verify_shape_and_sample_challenges;
use crate::verifier::fri::DuplexChallengerVariable;
use crate::verifier::TwoAdicMultiplicativeCosetVariable;

#[derive(DslVariable, Clone)]
pub struct BatchOpeningVariable<C: Config> {
    pub opened_values: Array<C, Array<C, Ext<C::F, C::EF>>>,
    pub opening_proof: Array<C, Array<C, Felt<C::F>>>,
}

pub struct TwoAdicPcsProofVariable<C: Config> {
    pub fri_proof: FriProofVariable<C>,
    pub query_openings: Array<C, Array<C, BatchOpeningVariable<C>>>,
}

#[derive(DslVariable, Clone)]
pub struct TwoAdicPcsRoundVariable<C: Config> {
    pub batch_commit: Commitment<C>,
    pub mats: Array<C, TwoAdicPcsMatsVariable<C>>,
}

#[allow(clippy::type_complexity)]
#[derive(DslVariable, Clone)]
pub struct TwoAdicPcsMatsVariable<C: Config> {
    pub domain: TwoAdicMultiplicativeCosetVariable<C>,
    pub points: Array<C, Ext<C::F, C::EF>>,
    pub values: Array<C, Array<C, Ext<C::F, C::EF>>>,
}

#[allow(clippy::type_complexity)]
#[allow(unused_variables)]
pub fn verify_two_adic_pcs<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfigVariable<C>,
    rounds: Array<C, TwoAdicPcsRoundVariable<C>>,
    proof: TwoAdicPcsProofVariable<C>,
    challenger: &mut DuplexChallengerVariable<C>,
) where
    C::EF: TwoAdicField,
{
    let alpha = challenger.sample_ext(builder);

    let code = builder.eval(C::N::from_canonical_usize(1));
    builder.print_v(code);
    let fri_challenges =
        verify_shape_and_sample_challenges(builder, config, &proof.fri_proof, challenger);
    let code = builder.eval(C::N::from_canonical_usize(1));
    builder.print_v(code);

    let commit_phase_commits_len = builder.materialize(proof.fri_proof.commit_phase_commits.len());
    let log_max_height: Var<_> = builder.eval(commit_phase_commits_len + config.log_blowup);

    let code = builder.eval(C::N::from_canonical_usize(2));
    builder.print_v(code);
    let mut reduced_openings: Array<C, Array<C, Ext<C::F, C::EF>>> =
        builder.array(proof.query_openings.len());
    builder
        .range(0, proof.query_openings.len())
        .for_each(|i, builder| {
            let query_opening = builder.get(&proof.query_openings, i);
            let index = builder.get(&fri_challenges.query_indices, i);
            let mut ro: Array<C, Ext<C::F, C::EF>> = builder.array(32);
            let zero: Ext<C::F, C::EF> = builder.eval(SymbolicExt::Const(C::EF::zero()));
            for j in 0..32 {
                builder.set(&mut ro, j, zero);
            }
            let mut alpha_pow: Array<C, Ext<C::F, C::EF>> = builder.array(32);
            let one: Ext<C::F, C::EF> = builder.eval(SymbolicExt::Const(C::EF::one()));
            for j in 0..32 {
                builder.set(&mut alpha_pow, j, one);
            }

            builder.range(0, rounds.len()).for_each(|j, builder| {
                let batch_opening = builder.get(&query_opening, j);
                let round = builder.get(&rounds, j);
                let batch_commit = round.batch_commit;
                let mats = round.mats;

                let mut batch_dims: Array<C, Dimensions<C>> = builder.array(mats.len());
                builder.range(0, mats.len()).for_each(|k, builder| {
                    let mat = builder.get(&mats, k);
                    let dim = Dimensions::<C> {
                        height: mat.domain.size(),
                    };
                    builder.set(&mut batch_dims, k, dim);
                });

                let index_bits = builder.num2bits_v(index);

                fri::verify_batch::<C, 1>(
                    builder,
                    &batch_commit,
                    batch_dims,
                    index_bits,
                    batch_opening.opened_values.clone(),
                    &batch_opening.opening_proof,
                );

                builder
                    .range(0, batch_opening.opened_values.len())
                    .for_each(|k, builder| {
                        let mat_opening = builder.get(&batch_opening.opened_values, k);
                        let mat = builder.get(&mats, k);
                        let mat_domain = mat.domain.size();
                        let mat_points = mat.points;
                        let mat_values = mat.values;

                        let log2_domain_size = mat.domain.log_n;
                        let log_height: Var<C::N> =
                            builder.eval(log2_domain_size + config.log_blowup);

                        let bits_reduced: Var<C::N> = builder.eval(log_max_height - log_height);
                        // TODO: divide by bits_reduced
                        let rev_reduced_index =
                            builder.reverse_bits_len(index, Usize::Var(log_height));
                        let rev_reduced_index = rev_reduced_index.materialize(builder);

                        let g = builder.generator();
                        let two_adic_generator = builder.two_adic_generator(Usize::Var(log_height));
                        let two_adic_generator_exp =
                            builder.exp_usize_f(two_adic_generator, Usize::Var(rev_reduced_index));
                        let x: Felt<C::F> = builder.eval(two_adic_generator_exp * g);

                        builder.range(0, mat_points.len()).for_each(|l, builder| {
                            let z: Ext<C::F, C::EF> = builder.get(&mat_points, l);
                            let ps_at_z = builder.get(&mat_values, l);
                            builder.range(0, ps_at_z.len()).for_each(|m, builder| {
                                let p_at_x: SymbolicExt<C::F, C::EF> =
                                    builder.get(&mat_opening, m).into();
                                let p_at_z: SymbolicExt<C::F, C::EF> =
                                    builder.get(&ps_at_z, m).into();
                                let quotient: SymbolicExt<C::F, C::EF> =
                                    (-p_at_z + p_at_x) / (-z + x);

                                let ro_at_log_height = builder.get(&ro, log_height);
                                let alpha_pow_at_log_height = builder.get(&alpha_pow, log_height);
                                let new_ro_at_log_height: Ext<C::F, C::EF> = builder
                                    .eval(ro_at_log_height + alpha_pow_at_log_height * quotient);

                                builder.set(&mut ro, log_height, new_ro_at_log_height);
                                builder.set(
                                    &mut alpha_pow,
                                    log_height,
                                    alpha_pow_at_log_height * alpha,
                                );
                            });
                        });
                    });
            });
            builder.set(&mut reduced_openings, i, ro);
        });
    let code = builder.eval(C::N::from_canonical_usize(2));
    builder.print_v(code);

    let code = builder.eval(C::N::from_canonical_usize(3));
    builder.print_v(code);
    fri::verify_challenges(
        builder,
        config,
        &proof.fri_proof,
        &fri_challenges,
        &reduced_openings,
    );
    let code = builder.eval(C::N::from_canonical_usize(3));
    builder.print_v(code);
}
