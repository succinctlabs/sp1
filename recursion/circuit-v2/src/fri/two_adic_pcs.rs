use std::iter::zip;

use itertools::Itertools;
use p3_commit::PolynomialSpace;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::AbstractField;
use p3_field::TwoAdicField;
use p3_fri::FriConfig;
use p3_matrix::Dimensions;
use p3_symmetric::Hash;
use sp1_core::utils::log2_strict_usize;
use sp1_core::utils::InnerChallengeMmcs;
use sp1_primitives::types::RecursionProgramType;
use sp1_recursion_compiler::circuit::CircuitV2Builder;
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::runtime::DIGEST_SIZE;

use super::types::DigestVariable;
use super::types::DimensionsVariable;
use super::types::FriConfigVariable;
use super::types::TwoAdicPcsMatsVariable;
use super::types::TwoAdicPcsProofVariable;
use super::types::TwoAdicPcsRoundVariable;
use super::{
    verify_batch, verify_challenges, verify_shape_and_sample_challenges,
    TwoAdicMultiplicativeCosetVariable,
};
use crate::challenger::DuplexChallengerVariable;
use crate::challenger::FeltChallenger;
use crate::commit::PcsVariable;

pub fn verify_two_adic_pcs<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig<InnerChallengeMmcs>,
    rounds: Vec<TwoAdicPcsRoundVariable<C>>,
    proof: TwoAdicPcsProofVariable<C>,
    challenger: &mut DuplexChallengerVariable<C>,
) {
    let mut input_ptr = builder.array::<FriFoldInput<_>>(1);
    let g = builder.generator();

    let log_blowup = config.log_blowup;
    let blowup = config.blowup();

    let alpha = challenger.sample_ext(builder);

    // builder.cycle_tracker("stage-d-1-verify-shape-and-sample-challenges");
    let fri_challenges =
        verify_shape_and_sample_challenges(builder, config, &proof.fri_proof, challenger);
    // builder.cycle_tracker("stage-d-1-verify-shape-and-sample-challenges");

    let commit_phase_commits_len = proof.fri_proof.commit_phase_commits.len();
    let log_global_max_height = commit_phase_commits_len + log_blowup;

    // builder.cycle_tracker("stage-d-2-fri-fold");
    let reduced_openings = zip(proof.query_openings, fri_challenges.query_indices)
        .map(|(query_opening, index_felt)| {
            let mut ro: Vec<Ext<C::F, C::EF>> =
                vec![builder.eval(SymbolicExt::from_f(C::EF::zero())); 32];
            let mut alpha_pow: Vec<Ext<C::F, C::EF>> =
                vec![builder.eval(SymbolicExt::from_f(C::EF::one())); 32];

            let num_commit_phase_commits = proof.fri_proof.commit_phase_commits.len();
            let log_max_height = num_commit_phase_commits + config.log_blowup;
            let mut index_bits = builder.num2bits_v2_f(index_felt);
            index_bits.truncate(log_max_height);

            for (batch_opening, round) in zip(query_opening, &rounds) {
                let batch_commit = &round.batch_commit;
                let mats = &round.mats;

                let batch_heights = mats
                    .iter()
                    .map(|mat| mat.domain.size() << config.log_blowup)
                    .collect_vec();
                let batch_dims = batch_heights
                    .iter()
                    .map(|&height| Dimensions { width: 0, height })
                    .collect_vec();
                // let mut batch_heights_log2: Vec<Var<C::N>> = builder.array(mats.len());
                // builder.range(0, mats.len()).for_each(|k, builder| {
                //     let mat = builder.get(&mats, k);
                //     let height_log2: Var<_> = builder.eval(mat.domain.log_n + log_blowup);
                //     batch_heights_log2[k] = height_log2;
                // });
                // let mut batch_dims: Vec<DimensionsVariable<C>> = builder.array(mats.len());
                // builder.range(0, mats.len()).for_each(|k, builder| {
                //     let mat = builder.get(&mats, k);
                //     let dim = DimensionsVariable::<C> {
                //         height: builder.eval(mat.domain.size() * blowup),
                //     };
                //     batch_dims[k] = dim;
                // });

                let batch_max_height = batch_heights.iter().max().expect("Empty batch?");
                let log_batch_max_height = log2_strict_usize(*batch_max_height);
                let bits_reduced = log_global_max_height - log_batch_max_height;
                let reduced_index_bits = index_bits[bits_reduced..].to_vec();
                verify_batch::<C, 1>(
                    builder,
                    &batch_commit,
                    batch_dims,
                    reduced_index_bits,
                    batch_opening.opened_values.clone(),
                    &batch_opening.opening_proof,
                );

                builder
                    .range(0, batch_opening.opened_values.len())
                    .for_each(|k, builder| {
                        let mat_opening = builder.get(&batch_opening.opened_values, k);
                        let mat = builder.get(&mats, k);
                        let mat_points = mat.points;
                        let mat_values = mat.values;

                        let log2_domain_size = mat.domain.log_n;
                        let log_height: Var<C::N> = builder.eval(log2_domain_size + log_blowup);

                        let bits_reduced: Var<C::N> =
                            builder.eval(log_global_max_height - log_height);
                        let index_bits_shifted = index_felt.shift(builder, bits_reduced);

                        let two_adic_generator = config.get_two_adic_generator(builder, log_height);
                        builder.cycle_tracker("exp_reverse_bits_len");

                        let two_adic_generator_exp: Felt<C::F> =
                            if matches!(builder.program_type, RecursionProgramType::Wrap) {
                                builder.exp_reverse_bits_len(
                                    two_adic_generator,
                                    &index_bits_shifted,
                                    log_height,
                                )
                            } else {
                                builder.exp_reverse_bits_len_fast(
                                    two_adic_generator,
                                    &index_bits_shifted,
                                    log_height,
                                )
                            };

                        builder.cycle_tracker("exp_reverse_bits_len");
                        let x: Felt<C::F> = builder.eval(two_adic_generator_exp * g);

                        builder.range(0, mat_points.len()).for_each(|l, builder| {
                            let z: Ext<C::F, C::EF> = builder.get(&mat_points, l);
                            let ps_at_z = builder.get(&mat_values, l);
                            let input = FriFoldInput {
                                z,
                                alpha,
                                x,
                                log_height,
                                mat_opening: mat_opening.clone(),
                                ps_at_z: ps_at_z.clone(),
                                alpha_pow: alpha_pow.clone(),
                                ro: ro.clone(),
                            };
                            input_ptr[0] = input;

                            let ps_at_z_len = ps_at_z.len();
                            builder.push(DslIr::FriFold(ps_at_z_len, input_ptr.clone()));
                        });
                    });
            }
            ro
        })
        .collect::<Vec<_>>();
    // builder.cycle_tracker("stage-d-2-fri-fold");

    // builder.cycle_tracker("stage-d-3-verify-challenges");
    verify_challenges(
        builder,
        config,
        &proof.fri_proof,
        &fri_challenges,
        &reduced_openings,
    );
    // builder.cycle_tracker("stage-d-3-verify-challenges");
}

impl<C: Config> FromConstant<C> for TwoAdicPcsRoundVariable<C>
where
    C::F: TwoAdicField,
{
    type Constant = (
        Hash<C::F, C::F, DIGEST_SIZE>,
        Vec<(TwoAdicMultiplicativeCoset<C::F>, Vec<(C::EF, Vec<C::EF>)>)>,
    );

    fn constant(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        let (commit_val, domains_and_openings_val) = value;

        // Allocate the commitment.
        let mut commit = builder.dyn_array::<Felt<_>>(DIGEST_SIZE);
        let commit_val: [C::F; DIGEST_SIZE] = commit_val.into();
        for (i, f) in commit_val.into_iter().enumerate() {
            builder.set(&mut commit, i, f);
        }

        let mut mats = domains_and_openings_val
            .into_iter()
            .enumerate()
            .map(|(i, (domain, openning))| {
                let domain = builder.constant::<TwoAdicMultiplicativeCosetVariable<_>>(domain);

                let points_val = openning.iter().map(|(p, _)| *p).collect::<Vec<_>>();
                let values_val = openning.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>();
                let mut points: Vec<_> = builder.dyn_array(points_val.len());
                for (j, point) in points_val.into_iter().enumerate() {
                    let el: Ext<_, _> = builder.eval(point.cons());
                    points[j] = el;
                }
                let mut values: Vec<_> = builder.dyn_array(values_val.len());
                for (j, val) in values_val.into_iter().enumerate() {
                    let mut tmp = builder.dyn_array(val.len());
                    for (k, v) in val.into_iter().enumerate() {
                        let el: Ext<_, _> = builder.eval(v.cons());
                        tmp[k] = el;
                    }
                    values[j] = tmp;
                }

                TwoAdicPcsMatsVariable {
                    domain,
                    points,
                    values,
                }
            })
            .collect();

        Self {
            batch_commit: commit,
            mats,
        }
    }
}

#[derive(Clone)]
pub struct TwoAdicFriPcsVariable<C: Config> {
    pub config: FriConfigVariable<C>,
}

impl<C: Config> PcsVariable<C, DuplexChallengerVariable<C>> for TwoAdicFriPcsVariable<C>
where
    C::F: TwoAdicField,
    C::EF: TwoAdicField,
{
    type Domain = TwoAdicMultiplicativeCosetVariable<C>;

    type Commitment = DigestVariable<C>;

    type Proof = TwoAdicPcsProofVariable<C>;

    fn natural_domain_for_log_degree(
        &self,
        builder: &mut Builder<C>,
        log_degree: Usize<C::N>,
    ) -> Self::Domain {
        self.config.get_subgroup(builder, log_degree)
    }

    fn verify(
        &self,
        builder: &mut Builder<C>,
        rounds: Vec<TwoAdicPcsRoundVariable<C>>,
        proof: Self::Proof,
        challenger: &mut DuplexChallengerVariable<C>,
    ) {
        verify_two_adic_pcs(builder, &self.config, rounds, proof, challenger)
    }
}

// pub mod tests {

//     use std::cmp::Reverse;
//     use std::collections::VecDeque;

//     use crate::challenger::CanObserveVariable;
//     use crate::challenger::DuplexChallengerVariable;
//     use crate::challenger::FeltChallenger;
//     use crate::commit::PcsVariable;
//     use crate::fri::types::TwoAdicPcsRoundVariable;
//     use crate::fri::TwoAdicFriPcsVariable;
//     use crate::fri::TwoAdicMultiplicativeCosetVariable;
//     use crate::hints::Hintable;
//     use crate::utils::const_fri_config;
//     use itertools::Itertools;
//     use p3_baby_bear::BabyBear;
//     use p3_challenger::CanObserve;
//     use p3_challenger::FieldChallenger;
//     use p3_commit::Pcs;
//     use p3_commit::TwoAdicMultiplicativeCoset;
//     use p3_field::AbstractField;
//     use p3_matrix::dense::RowMajorMatrix;
//     use rand::rngs::OsRng;
//     use sp1_core::utils::baby_bear_poseidon2::compressed_fri_config;
//     use sp1_core::utils::inner_perm;
//     use sp1_core::utils::InnerChallenge;
//     use sp1_core::utils::InnerChallenger;
//     use sp1_core::utils::InnerCompress;
//     use sp1_core::utils::InnerDft;
//     use sp1_core::utils::InnerHash;
//     use sp1_core::utils::InnerPcs;
//     use sp1_core::utils::InnerPcsProof;
//     use sp1_core::utils::InnerVal;
//     use sp1_core::utils::InnerValMmcs;
//     use sp1_recursion_compiler::config::InnerConfig;
//     use sp1_recursion_compiler::ir::Array;
//     use sp1_recursion_compiler::ir::Builder;
//     use sp1_recursion_compiler::ir::Usize;
//     use sp1_recursion_compiler::ir::Var;
//     use sp1_recursion_core::air::Block;
//     use sp1_recursion_core::runtime::RecursionProgram;
//     use sp1_recursion_core::runtime::DIGEST_SIZE;

//     pub fn build_test_fri_with_cols_and_log2_rows(
//         nb_cols: usize,
//         nb_log2_rows: usize,
//     ) -> (RecursionProgram<BabyBear>, VecDeque<Vec<Block<BabyBear>>>) {
//         let mut rng = &mut OsRng;
//         let log_degrees = &[nb_log2_rows];
//         let perm = inner_perm();
//         let fri_config = compressed_fri_config();
//         let hash = InnerHash::new(perm.clone());
//         let compress = InnerCompress::new(perm.clone());
//         let val_mmcs = InnerValMmcs::new(hash, compress);
//         let dft = InnerDft {};
//         let pcs_val: InnerPcs = InnerPcs::new(
//             log_degrees.iter().copied().max().unwrap(),
//             dft,
//             val_mmcs,
//             fri_config,
//         );

//         // Generate proof.
//         let domains_and_polys = log_degrees
//             .iter()
//             .map(|&d| {
//                 (
//                     <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::natural_domain_for_degree(
//                         &pcs_val,
//                         1 << d,
//                     ),
//                     RowMajorMatrix::<InnerVal>::rand(&mut rng, 1 << d, nb_cols),
//                 )
//             })
//             .sorted_by_key(|(dom, _)| Reverse(dom.log_n))
//             .collect::<Vec<_>>();
//         let (commit, data) = <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::commit(
//             &pcs_val,
//             domains_and_polys.clone(),
//         );
//         let mut challenger = InnerChallenger::new(perm.clone());
//         challenger.observe(commit);
//         let zeta = challenger.sample_ext_element::<InnerChallenge>();
//         let points = domains_and_polys
//             .iter()
//             .map(|_| vec![zeta])
//             .collect::<Vec<_>>();
//         let (opening, proof) = pcs_val.open(vec![(&data, points)], &mut challenger);

//         // Verify proof.
//         let mut challenger = InnerChallenger::new(perm.clone());
//         challenger.observe(commit);
//         challenger.sample_ext_element::<InnerChallenge>();
//         let os: Vec<(
//             TwoAdicMultiplicativeCoset<InnerVal>,
//             Vec<(InnerChallenge, Vec<InnerChallenge>)>,
//         )> = domains_and_polys
//             .iter()
//             .zip(&opening[0])
//             .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
//             .collect();
//         pcs_val
//             .verify(vec![(commit, os.clone())], &proof, &mut challenger)
//             .unwrap();

//         // Test the recursive Pcs.
//         let mut builder = Builder::<InnerConfig>::default();
//         let config = const_fri_config(&mut builder, &compressed_fri_config());
//         let pcs = TwoAdicFriPcsVariable { config };
//         let rounds =
//             builder.constant::<Vec<TwoAdicPcsRoundVariable<_>>>(vec![(commit, os.clone())]);

//         // Test natural domain for degree.
//         for log_d_val in log_degrees.iter() {
//             let log_d: Var<_> = builder.eval(InnerVal::from_canonical_usize(*log_d_val));
//             let domain = pcs.natural_domain_for_log_degree(&mut builder, Usize::Var(log_d));

//             let domain_val =
//                 <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::natural_domain_for_degree(
//                     &pcs_val,
//                     1 << log_d_val,
//                 );

//             let expected_domain: TwoAdicMultiplicativeCosetVariable<_> =
//                 builder.constant(domain_val);

//             builder.assert_eq::<TwoAdicMultiplicativeCosetVariable<_>>(domain, expected_domain);
//         }

//         // Test proof verification.
//         let proofvar = InnerPcsProof::read(&mut builder);
//         let mut challenger = DuplexChallengerVariable::new(&mut builder);
//         let commit = <[InnerVal; DIGEST_SIZE]>::from(commit).to_vec();
//         let commit = builder.constant::<Vec<_>>(commit);
//         challenger.observe(&mut builder, commit);
//         challenger.sample_ext(&mut builder);
//         pcs.verify(&mut builder, rounds, proofvar, &mut challenger);
//         builder.halt();

//         let program = builder.compile_program();
//         let mut witness_stream = VecDeque::new();
//         witness_stream.extend(proof.write());
//         (program, witness_stream)
//     }

//     #[test]
//     fn test_two_adic_fri_pcs_single_batch() {
//         use sp1_recursion_core::stark::utils::{run_test_recursion, TestConfig};
//         let (program, witness) = build_test_fri_with_cols_and_log2_rows(10, 16);

//         // We don't test with the config TestConfig::WideDeg17Wrap, since it doesn't have the
//         // `ExpReverseBitsLen` chip.
//         run_test_recursion(program.clone(), Some(witness.clone()), TestConfig::WideDeg3);
//         run_test_recursion(program, Some(witness), TestConfig::SkinnyDeg7);
//     }
// }
