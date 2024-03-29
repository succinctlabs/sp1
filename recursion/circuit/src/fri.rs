use itertools::{izip, Itertools};
use p3_commit::{PolynomialSpace, TwoAdicMultiplicativeCoset};
use p3_field::AbstractField;
use p3_field::TwoAdicField;
use p3_fri::FriConfig;
use p3_matrix::Dimensions;
use p3_util::log2_strict_usize;
use sp1_recursion_compiler::ir::{Builder, Config, Felt};
use sp1_recursion_compiler::prelude::Array;
use sp1_recursion_compiler::prelude::MemVariable;
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_compiler::OuterConfig;
use sp1_recursion_core::stark::config::OuterChallengeMmcs;
use sp1_recursion_derive::DslVariable;

use crate::mmcs::{verify_batch, OuterDigest};
use crate::{challenger::MultiFieldChallengerVariable, DIGEST_SIZE};

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L27
pub fn verify_shape_and_sample_challenges<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig<OuterChallengeMmcs>,
    proof: &FriProofVariable<C>,
    challenger: &mut MultiFieldChallengerVariable<C>,
) -> FriChallenges<C> {
    let mut betas = vec![];

    #[allow(clippy::never_loop)]
    for i in 0..proof.commit_phase_commits.len() {
        let commitment: [Var<C::N>; DIGEST_SIZE] =
            proof.commit_phase_commits[i].try_into().unwrap();
        challenger.observe_commitment(builder, commitment);
        let sample = challenger.sample_ext(builder);
        betas.push(sample);
    }

    assert_eq!(proof.query_proofs.len(), config.num_queries);

    challenger.check_witness(builder, config.proof_of_work_bits, proof.pow_witness);

    let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;
    let query_indices: Vec<Var<_>> = (0..config.num_queries)
        .map(|_| challenger.sample_bits(builder, log_max_height))
        .collect();

    FriChallenges {
        query_indices,
        betas,
    }
}

#[derive(Clone)]
pub struct BatchOpeningVariable<C: Config> {
    pub opened_values: Vec<Vec<Vec<Felt<C::F>>>>,
    pub opening_proof: Vec<OuterDigest<C>>,
}

#[derive(Clone)]
pub struct TwoAdicPcsProofVariable<C: Config> {
    pub fri_proof: FriProofVariable<C>,
    pub query_openings: Vec<Vec<BatchOpeningVariable<C>>>,
}

#[derive(Clone)]
pub struct TwoAdicPcsRoundVariable<C: Config> {
    pub batch_commit: OuterDigest<C>,
    pub mats: Vec<TwoAdicPcsMatsVariable<C>>,
}

#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct TwoAdicPcsMatsVariable<C: Config> {
    pub domain: TwoAdicMultiplicativeCoset<C::F>,
    pub points: Vec<Ext<C::F, C::EF>>,
    pub values: Vec<Vec<Ext<C::F, C::EF>>>,
}

pub fn verify_two_adic_pcs<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig<OuterChallengeMmcs>,
    proof: &TwoAdicPcsProofVariable<C>,
    challenger: &mut MultiFieldChallengerVariable<C>,
    rounds: Vec<TwoAdicPcsRoundVariable<C>>,
) {
    let alpha = challenger.sample_ext(builder);
    let fri_challenges =
        verify_shape_and_sample_challenges(builder, config, &proof.fri_proof, challenger);

    let log_global_max_height = proof.fri_proof.commit_phase_commits.len() + config.log_blowup;

    let reduced_openings = proof.query_openings[0..1]
        .iter()
        .zip(&fri_challenges.query_indices)
        .map(|(query_opening, &index)| {
            let mut ro: [Ext<C::F, C::EF>; 32] =
                [builder.eval(SymbolicExt::Const(C::EF::zero())); 32];
            let mut alpha_pow: [Ext<C::F, C::EF>; 32] =
                [builder.eval(SymbolicExt::Const(C::EF::one())); 32];

            for (batch_opening, round) in izip!(query_opening, &rounds) {
                let batch_commit = round.batch_commit;
                let mats = &round.mats;
                let batch_heights = mats
                    .iter()
                    .map(|mat| mat.domain.size() << config.log_blowup)
                    .collect_vec();
                let batch_dims = batch_heights
                    .iter()
                    .map(|&height| Dimensions { width: 0, height })
                    .collect_vec();

                let batch_max_height = batch_heights.iter().max().expect("Empty batch?");
                let log_batch_max_height = log2_strict_usize(*batch_max_height);
                let bits_reduced = log_global_max_height - log_batch_max_height;

                let index_bits = builder.num2bits_v_circuit(index, 256);
                let reduced_index_bits = index_bits[bits_reduced..].to_vec();

                verify_batch::<C, 1>(
                    builder,
                    batch_commit,
                    batch_dims,
                    reduced_index_bits,
                    batch_opening.opened_values.clone(),
                    batch_opening.opening_proof.clone(),
                );
                for (mat_opening, mat) in izip!(&batch_opening.opened_values, mats) {
                    let mat_opening = mat_opening.clone()[0].clone();
                    let mat_domain = mat.domain;
                    let mat_points = &mat.points;
                    let mat_values = &mat.values;
                    let log_height = log2_strict_usize(mat_domain.size()) + config.log_blowup;

                    let bits_reduced = log_global_max_height - log_height;
                    let rev_reduced_index = builder
                        .reverse_bits_len_circuit(index_bits[bits_reduced..].to_vec(), log_height);

                    let g = builder.generator();
                    let two_adic_generator: Felt<_> =
                        builder.eval(C::F::two_adic_generator(log_height));
                    let two_adic_generator_exp =
                        builder.exp_usize_f_bits(two_adic_generator, rev_reduced_index);
                    let x: Felt<_> = builder.eval(g * two_adic_generator_exp);

                    for (z, ps_at_z) in izip!(mat_points, mat_values) {
                        for (p_at_x, &p_at_z) in izip!(mat_opening.clone(), ps_at_z) {
                            let quotient: SymbolicExt<C::F, C::EF> = (-p_at_z + p_at_x) / (-*z + x);
                            ro[log_height] =
                                builder.eval(ro[log_height] + alpha_pow[log_height] * quotient);
                            alpha_pow[log_height] = builder.eval(alpha_pow[log_height] * alpha);
                        }
                    }
                }
            }
            ro
        })
        .collect::<Vec<_>>();
}

pub fn verify_challenges<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig<OuterChallengeMmcs>,
    proof: &FriProofVariable<C>,
    challenges: &FriChallenges<C>,
    reduced_openings: Vec<Vec<[Ext<C::F, C::EF>; 32]>>,
) {
    let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;
    for (&index, query_proof, ro) in izip!(
        &challenges.query_indices,
        &proof.query_proofs,
        reduced_openings
    ) {
        let folded_eval = verify_query(
            builder,
            proof.commit_phase_commits.clone(),
            index,
            query_proof.clone(),
            challenges.betas.clone(),
            ro,
            log_max_height,
        );

        builder.assert_ext_eq(folded_eval, proof.final_poly);
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::explicit_counter_loop)]
pub fn verify_query<C: Config>(
    builder: &mut Builder<C>,
    commit_phase_commits: Vec<OuterDigest<C>>,
    index: Var<C::N>,
    proof: FriQueryProofVariable<C>,
    betas: Vec<Ext<C::F, C::EF>>,
    reduced_openings: Vec<[Ext<C::F, C::EF>; 32]>,
    log_max_height: usize,
) -> Ext<C::F, C::EF> {
    let mut folded_eval: Ext<C::F, C::EF> = builder.eval(SymbolicExt::Const(C::EF::zero()));
    let two_adic_generator = builder.eval(SymbolicExt::Const(C::EF::two_adic_generator(
        log_max_height,
    )));
    let index_bits = builder.num2bits_v_circuit(index, 256);
    let rev_reduced_index = builder.reverse_bits_len_circuit(index_bits.clone(), log_max_height);
    let mut x = builder.exp_usize_ef_bits(two_adic_generator, rev_reduced_index);

    let mut offset = 0;
    for (log_folded_height, commit, step, beta) in izip!(
        (0..log_max_height).rev(),
        commit_phase_commits,
        &proof.commit_phase_openings,
        betas,
    ) {
        folded_eval = builder.eval(folded_eval + reduced_openings[log_folded_height + 1]);

        let one: Var<_> = builder.eval(C::N::one());
        let index_sibling: Var<_> = builder.eval(one - index_bits.clone()[0]);
        let index_pair = &index_bits[offset..];

        let evals_ext = [
            builder.select_ef(index_sibling, folded_eval, step.sibling_value),
            builder.select_ef(index_sibling, step.sibling_value, folded_eval),
        ];
        let evals_felt = vec![
            builder.ext2felt_circuit(evals_ext[0]).to_vec(),
            builder.ext2felt_circuit(evals_ext[1]).to_vec(),
        ];

        let dims = &[Dimensions {
            width: 2,
            height: (1 << log_folded_height),
        }];
        verify_batch::<C, 4>(
            builder,
            commit,
            dims.to_vec(),
            index_pair.to_vec(),
            [evals_felt].to_vec(),
            step.opening_proof.clone(),
        );

        let xs_new = builder.eval(x * C::EF::two_adic_generator(1));
        let xs = [
            builder.select_ef(index_sibling, x, xs_new),
            builder.select_ef(index_sibling, xs_new, x),
        ];
        folded_eval = builder
            .eval(evals_ext[0] + (beta - xs[0]) * (evals_ext[1] - evals_ext[0]) / (xs[1] - xs[0]));
        x = builder.eval(x * x);
        offset += 1;
    }

    folded_eval
}

// pub fn verify_query<C: Config>(
//     builder: &mut Builder<C>,
//     config: &FriConfig<OuterChallengeMmcs>,
//     commit_phase_commits: &Array<C, Array<C, Var<C::N>>>,
//     index: Var<C::N>,
//     proof: &FriQueryProofVariable<C>,
//     betas: &Array<C, Ext<C::F, C::EF>>,
//     reduced_openings: &Array<C, Ext<C::F, C::EF>>,
//     log_max_height: usize,
// ) -> Ext<C::F, C::EF>
// where
//     C::EF: TwoAdicField,
// {
//     let folded_eval: Ext<C::F, C::EF> = builder.eval(C::F::zero());
//     let two_adic_generator_ef = builder.eval(SymbolicExt::Const(C::EF::two_adic_generator(
//         log_max_height,
//     )));
//     let power = builder.reverse_bits_len(index, log_max_height);
//     let x = builder.exp_usize_ef(two_adic_generator_ef, power);
//     let index_bits = builder.num2bits_v_circuit(index, 32);

//     // builder
//     //     .range(0, commit_phase_commits.len())
//     //     .for_each(|i, builder| {
//     //         let log_folded_height: Var<_> = builder.eval(log_max_height - i - C::N::one());
//     //         let log_folded_height_plus_one: Var<_> = builder.eval(log_folded_height + C::N::one());
//     //         let commit = builder.get(commit_phase_commits, i);
//     //         let step = builder.get(&proof.commit_phase_openings, i);
//     //         let beta = builder.get(betas, i);

//     //         let reduced_opening = builder.get(reduced_openings, log_folded_height_plus_one);
//     //         builder.assign(folded_eval, folded_eval + reduced_opening);

//     //         let index_bit = builder.get(&index_bits, i);
//     //         let index_sibling_mod_2: Var<C::N> =
//     //             builder.eval(SymbolicVar::Const(C::N::one()) - index_bit);
//     //         let i_plus_one = builder.eval(i + C::N::one());
//     //         let index_pair = index_bits.shift(builder, i_plus_one);

//     //         let mut evals: Array<C, Ext<C::F, C::EF>> = builder.array(2);
//     //         builder.set(&mut evals, 0, folded_eval);
//     //         builder.set(&mut evals, 1, folded_eval);
//     //         builder.set(&mut evals, index_sibling_mod_2, step.sibling_value);

//     //         let two: Var<C::N> = builder.eval(C::N::from_canonical_u32(2));
//     //         let dims = Dimensions::<C> {
//     //             height: builder.exp_usize_v(two, Usize::Var(log_folded_height)),
//     //         };
//     //         let mut dims_slice: Array<C, Dimensions<C>> = builder.array(1);
//     //         builder.set(&mut dims_slice, 0, dims);

//     //         let mut opened_values = builder.array(1);
//     //         builder.set(&mut opened_values, 0, evals.clone());
//     //         verify_batch::<C, 4>(
//     //             builder,
//     //             &commit,
//     //             dims_slice,
//     //             index_pair,
//     //             opened_values,
//     //             &step.opening_proof,
//     //         );

//     //         let mut xs: Array<C, Ext<C::F, C::EF>> = builder.array(2);
//     //         let two_adic_generator_one = builder.two_adic_generator(Usize::Const(1));
//     //         builder.set(&mut xs, 0, x);
//     //         builder.set(&mut xs, 1, x);
//     //         builder.set(&mut xs, index_sibling_mod_2, x * two_adic_generator_one);

//     //         let xs_0 = builder.get(&xs, 0);
//     //         let xs_1 = builder.get(&xs, 1);
//     //         let eval_0 = builder.get(&evals, 0);
//     //         let eval_1 = builder.get(&evals, 1);
//     //         builder.assign(
//     //             folded_eval,
//     //             eval_0 + (beta - xs_0) * (eval_1 - eval_0) / (xs_1 - xs_0),
//     //         );

//     //         builder.assign(x, x * x);
//     //     });

//     // folded_eval
//     todo!()
// }

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L12
#[derive(Clone)]
pub struct FriProofVariable<C: Config> {
    pub commit_phase_commits: Vec<OuterDigest<C>>,
    pub query_proofs: Vec<FriQueryProofVariable<C>>,
    pub final_poly: Ext<C::F, C::EF>,
    pub pow_witness: Felt<C::F>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L32
#[derive(Clone)]
pub struct FriCommitPhaseProofStepVariable<C: Config> {
    pub sibling_value: Ext<C::F, C::EF>,
    pub opening_proof: Vec<OuterDigest<C>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L23
#[derive(Clone)]
pub struct FriQueryProofVariable<C: Config> {
    pub commit_phase_openings: Vec<FriCommitPhaseProofStepVariable<C>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L22
#[derive(Clone)]
pub struct FriChallenges<C: Config> {
    pub query_indices: Vec<Var<C::N>>,
    pub betas: Vec<Ext<C::F, C::EF>>,
}

#[cfg(test)]
mod tests {

    use std::ops::Mul;

    use itertools::Itertools;
    use p3_bn254_fr::Bn254Fr;
    use p3_challenger::{CanObserve, CanSample, FieldChallenger};
    use p3_commit::{Pcs, TwoAdicMultiplicativeCoset};
    use p3_field::AbstractField;
    use p3_fri::{verifier, TwoAdicFriPcsProof};
    use p3_matrix::dense::RowMajorMatrix;
    use rand::rngs::OsRng;
    use serial_test::serial;
    use sp1_recursion_compiler::{
        constraints::{gnark_ffi, ConstraintBackend},
        ir::{Builder, Ext, Felt, SymbolicExt, Var},
        OuterConfig,
    };
    use sp1_recursion_core::stark::config::{
        outer_fri_config, outer_perm, OuterChallenge, OuterChallengeMmcs, OuterChallenger,
        OuterCompress, OuterDft, OuterFriProof, OuterHash, OuterPcs, OuterVal, OuterValMmcs,
    };

    use super::{
        verify_shape_and_sample_challenges, verify_two_adic_pcs, FriCommitPhaseProofStepVariable,
        FriProofVariable, TwoAdicPcsProofVariable, TwoAdicPcsRoundVariable,
    };
    use crate::{
        challenger::MultiFieldChallengerVariable,
        fri::{BatchOpeningVariable, FriQueryProofVariable, TwoAdicPcsMatsVariable},
        mmcs::OuterDigest,
        DIGEST_SIZE,
    };

    pub fn const_fri_proof(
        builder: &mut Builder<OuterConfig>,
        fri_proof: OuterFriProof,
    ) -> FriProofVariable<OuterConfig> {
        // Set the commit phase commits.
        let commit_phase_commits = fri_proof
            .commit_phase_commits
            .iter()
            .map(|commit| {
                let commit: [Bn254Fr; DIGEST_SIZE] = (*commit).into();
                let commit: Var<_> = builder.eval(commit[0]);
                [commit; DIGEST_SIZE]
            })
            .collect::<Vec<_>>();

        // Set the query proofs.
        let query_proofs = fri_proof
            .query_proofs
            .iter()
            .map(|query_proof| {
                let commit_phase_openings = query_proof
                    .commit_phase_openings
                    .iter()
                    .map(|commit_phase_opening| {
                        let sibling_value =
                            builder.eval(SymbolicExt::Const(commit_phase_opening.sibling_value));
                        let opening_proof = commit_phase_opening
                            .opening_proof
                            .iter()
                            .map(|sibling| {
                                let commit: Var<_> = builder.eval(sibling[0]);
                                [commit; DIGEST_SIZE]
                            })
                            .collect::<Vec<_>>();
                        FriCommitPhaseProofStepVariable {
                            sibling_value,
                            opening_proof,
                        }
                    })
                    .collect::<Vec<_>>();
                FriQueryProofVariable {
                    commit_phase_openings,
                }
            })
            .collect::<Vec<_>>();

        // Initialize the FRI proof variable.
        FriProofVariable {
            commit_phase_commits,
            query_proofs,
            final_poly: builder.eval(SymbolicExt::Const(fri_proof.final_poly)),
            pow_witness: builder.eval(fri_proof.pow_witness),
        }
    }

    pub fn const_two_adic_pcs_proof(
        builder: &mut Builder<OuterConfig>,
        proof: TwoAdicFriPcsProof<OuterVal, OuterChallenge, OuterValMmcs, OuterChallengeMmcs>,
    ) -> TwoAdicPcsProofVariable<OuterConfig> {
        let fri_proof = const_fri_proof(builder, proof.fri_proof);
        let query_openings = proof
            .query_openings
            .iter()
            .map(|query_opening| {
                query_opening
                    .iter()
                    .map(|opening| BatchOpeningVariable {
                        opened_values: opening
                            .opened_values
                            .iter()
                            .map(|opened_value| {
                                opened_value
                                    .iter()
                                    .map(|value| vec![builder.eval::<Felt<OuterVal>, _>(*value)])
                                    .collect::<Vec<_>>()
                            })
                            .collect::<Vec<_>>(),
                        opening_proof: opening
                            .opening_proof
                            .iter()
                            .map(|opening_proof| [builder.eval(opening_proof[0])])
                            .collect::<Vec<_>>(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        TwoAdicPcsProofVariable {
            fri_proof,
            query_openings,
        }
    }

    pub fn const_two_adic_pcs_rounds(
        builder: &mut Builder<OuterConfig>,
        commit: [Bn254Fr; DIGEST_SIZE],
        os: Vec<(
            TwoAdicMultiplicativeCoset<OuterVal>,
            Vec<(OuterChallenge, Vec<OuterChallenge>)>,
        )>,
    ) -> (
        OuterDigest<OuterConfig>,
        Vec<TwoAdicPcsRoundVariable<OuterConfig>>,
    ) {
        let commit: OuterDigest<OuterConfig> = [builder.eval(commit[0])];

        let mut mats = Vec::new();
        for (m, (domain, poly)) in os.into_iter().enumerate() {
            let points: Vec<Ext<OuterVal, OuterChallenge>> = poly
                .iter()
                .map(|(p, _)| builder.eval(SymbolicExt::Const(*p)))
                .collect::<Vec<_>>();
            let values: Vec<Vec<Ext<OuterVal, OuterChallenge>>> = poly
                .iter()
                .map(|(_, v)| {
                    v.clone()
                        .iter()
                        .map(|t| builder.eval(SymbolicExt::Const(*t)))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let mat = TwoAdicPcsMatsVariable {
                domain,
                points,
                values,
            };
            mats.push(mat);
        }

        (
            commit,
            vec![TwoAdicPcsRoundVariable {
                batch_commit: commit,
                mats,
            }],
        )
    }

    #[test]
    #[serial]
    fn test_fri_verify_shape_and_sample_challenges() {
        let mut rng = &mut OsRng;
        let log_degrees = &[16, 9, 7, 4, 2];
        let perm = outer_perm();
        let fri_config = outer_fri_config();
        let hash = OuterHash::new(perm.clone()).unwrap();
        let compress = OuterCompress::new(perm.clone());
        let val_mmcs = OuterValMmcs::new(hash, compress);
        let dft = OuterDft {};
        let pcs: OuterPcs = OuterPcs::new(
            log_degrees.iter().copied().max().unwrap(),
            dft,
            val_mmcs,
            fri_config,
        );

        // Generate proof.
        let domains_and_polys = log_degrees
            .iter()
            .map(|&d| {
                (
                    <OuterPcs as Pcs<OuterChallenge, OuterChallenger>>::natural_domain_for_degree(
                        &pcs,
                        1 << d,
                    ),
                    RowMajorMatrix::<OuterVal>::rand(&mut rng, 1 << d, 10),
                )
            })
            .collect::<Vec<_>>();
        let (commit, data) = <OuterPcs as Pcs<OuterChallenge, OuterChallenger>>::commit(
            &pcs,
            domains_and_polys.clone(),
        );
        let mut challenger = OuterChallenger::new(perm.clone()).unwrap();
        challenger.observe(commit);
        let zeta = challenger.sample_ext_element::<OuterChallenge>();
        let points = domains_and_polys
            .iter()
            .map(|_| vec![zeta])
            .collect::<Vec<_>>();
        let (_, proof) = pcs.open(vec![(&data, points)], &mut challenger);

        // Verify proof.
        let mut challenger = OuterChallenger::new(perm.clone()).unwrap();
        challenger.observe(commit);
        let _: OuterChallenge = challenger.sample();
        let fri_challenges_gt = verifier::verify_shape_and_sample_challenges(
            &outer_fri_config(),
            &proof.fri_proof,
            &mut challenger,
        )
        .unwrap();

        // Define circuit.
        let mut builder = Builder::<OuterConfig>::default();
        let config = outer_fri_config();
        let fri_proof = const_fri_proof(&mut builder, proof.fri_proof);

        let mut challenger = MultiFieldChallengerVariable::new(&mut builder);
        let commit: [Bn254Fr; DIGEST_SIZE] = commit.into();
        let commit: Var<_> = builder.eval(commit[0]);
        challenger.observe_commitment(&mut builder, [commit]);
        let _ = challenger.sample_ext(&mut builder);
        let fri_challenges =
            verify_shape_and_sample_challenges(&mut builder, &config, &fri_proof, &mut challenger);

        for i in 0..fri_challenges_gt.betas.len() {
            builder.assert_ext_eq(
                SymbolicExt::Const(fri_challenges_gt.betas[i]),
                fri_challenges.betas[i],
            );
        }

        for i in 0..fri_challenges_gt.query_indices.len() {
            builder.assert_var_eq(
                Bn254Fr::from_canonical_usize(fri_challenges_gt.query_indices[i]),
                fri_challenges.query_indices[i],
            );
        }

        let mut backend = ConstraintBackend::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        gnark_ffi::test_circuit(constraints);
    }

    #[test]
    #[serial]
    fn test_verify_two_adic_pcs() {
        let mut rng = &mut OsRng;
        let log_degrees = &[16, 9, 7, 4, 2];
        let perm = outer_perm();
        let fri_config = outer_fri_config();
        let hash = OuterHash::new(perm.clone()).unwrap();
        let compress = OuterCompress::new(perm.clone());
        let val_mmcs = OuterValMmcs::new(hash, compress);
        let dft = OuterDft {};
        let pcs: OuterPcs = OuterPcs::new(
            log_degrees.iter().copied().max().unwrap(),
            dft,
            val_mmcs,
            fri_config,
        );

        // Generate proof.
        let domains_and_polys = log_degrees
            .iter()
            .map(|&d| {
                (
                    <OuterPcs as Pcs<OuterChallenge, OuterChallenger>>::natural_domain_for_degree(
                        &pcs,
                        1 << d,
                    ),
                    RowMajorMatrix::<OuterVal>::rand(&mut rng, 1 << d, 10),
                )
            })
            .collect::<Vec<_>>();
        let (commit, data) = <OuterPcs as Pcs<OuterChallenge, OuterChallenger>>::commit(
            &pcs,
            domains_and_polys.clone(),
        );
        let mut challenger = OuterChallenger::new(perm.clone()).unwrap();
        challenger.observe(commit);
        let zeta = challenger.sample_ext_element::<OuterChallenge>();
        let points = domains_and_polys
            .iter()
            .map(|_| vec![zeta])
            .collect::<Vec<_>>();
        let (opening, proof) = pcs.open(vec![(&data, points)], &mut challenger);

        // Verify proof.
        let mut challenger = OuterChallenger::new(perm.clone()).unwrap();
        challenger.observe(commit);
        challenger.sample_ext_element::<OuterChallenge>();
        let os: Vec<(
            TwoAdicMultiplicativeCoset<OuterVal>,
            Vec<(OuterChallenge, Vec<OuterChallenge>)>,
        )> = domains_and_polys
            .iter()
            .zip(&opening[0])
            .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
            .collect();
        pcs.verify(vec![(commit, os.clone())], &proof, &mut challenger)
            .unwrap();

        // Define circuit.
        let mut builder = Builder::<OuterConfig>::default();
        let config = outer_fri_config();
        let proof = const_two_adic_pcs_proof(&mut builder, proof);
        let (commit, rounds) = const_two_adic_pcs_rounds(&mut builder, commit.into(), os);
        let mut challenger = MultiFieldChallengerVariable::new(&mut builder);
        challenger.observe_commitment(&mut builder, commit);
        challenger.sample_ext(&mut builder);
        verify_two_adic_pcs(&mut builder, &config, &proof, &mut challenger, rounds);

        let mut backend = ConstraintBackend::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        gnark_ffi::test_circuit(constraints);
    }
}
