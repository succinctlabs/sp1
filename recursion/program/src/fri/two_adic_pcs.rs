use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::AbstractField;
use p3_field::TwoAdicField;
use p3_symmetric::Hash;
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

#[allow(clippy::type_complexity)]
pub fn verify_two_adic_pcs<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfigVariable<C>,
    rounds: Array<C, TwoAdicPcsRoundVariable<C>>,
    proof: TwoAdicPcsProofVariable<C>,
    challenger: &mut DuplexChallengerVariable<C>,
) where
    C::F: TwoAdicField,
    C::EF: TwoAdicField,
{
    let alpha = challenger.sample_ext(builder);

    let fri_challenges =
        verify_shape_and_sample_challenges(builder, config, &proof.fri_proof, challenger);

    let commit_phase_commits_len = proof
        .fri_proof
        .commit_phase_commits
        .len()
        .materialize(builder);
    let log_global_max_height: Var<_> = builder.eval(commit_phase_commits_len + config.log_blowup);

    let mut reduced_openings: Array<C, Array<C, Ext<C::F, C::EF>>> =
        builder.array(proof.query_openings.len());
    builder
        .range(0, proof.query_openings.len())
        .for_each(|i, builder| {
            let query_opening = builder.get(&proof.query_openings, i);
            let index_bits = builder.get(&fri_challenges.query_indices, i);
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

                let mut batch_heights_log2: Array<C, Var<C::N>> = builder.array(mats.len());
                builder.range(0, mats.len()).for_each(|k, builder| {
                    let mat = builder.get(&mats, k);
                    let height_log2: Var<_> = builder.eval(mat.domain.log_n + config.log_blowup);
                    builder.set(&mut batch_heights_log2, k, height_log2);
                });
                let mut batch_dims: Array<C, DimensionsVariable<C>> = builder.array(mats.len());
                builder.range(0, mats.len()).for_each(|k, builder| {
                    let mat = builder.get(&mats, k);
                    let dim = DimensionsVariable::<C> {
                        height: builder.eval(mat.domain.size() * C::N::two()), // TODO: fix this to use blowup
                    };
                    builder.set(&mut batch_dims, k, dim);
                });

                let log_batch_max_height = builder.get(&batch_heights_log2, 0);
                let bits_reduced: Var<_> =
                    builder.eval(log_global_max_height - log_batch_max_height);
                let index_bits_shifted_v1 = index_bits.shift(builder, bits_reduced);
                verify_batch::<C, 1>(
                    builder,
                    &batch_commit,
                    batch_dims,
                    index_bits_shifted_v1,
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
                        let log_height: Var<C::N> =
                            builder.eval(log2_domain_size + config.log_blowup);

                        let bits_reduced: Var<C::N> =
                            builder.eval(log_global_max_height - log_height);
                        let index_bits_shifted = index_bits.shift(builder, bits_reduced);

                        let g = builder.generator();
                        let two_adic_generator = config.get_two_adic_generator(builder, log_height);
                        let two_adic_generator_exp = builder.exp_reverse_bits_len(
                            two_adic_generator,
                            &index_bits_shifted,
                            log_height,
                        );
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

                                builder.set(
                                    &mut ro,
                                    log_height,
                                    ro_at_log_height + alpha_pow_at_log_height * quotient,
                                );
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

    verify_challenges(
        builder,
        config,
        &proof.fri_proof,
        &fri_challenges,
        &reduced_openings,
    );
}

impl<C: Config> FromConstant<C> for TwoAdicPcsRoundVariable<C>
where
    C::F: TwoAdicField,
{
    type Constant = (
        Hash<C::F, C::F, DIGEST_SIZE>,
        Vec<(TwoAdicMultiplicativeCoset<C::F>, Vec<(C::EF, Vec<C::EF>)>)>,
    );

    fn eval_const(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        let (commit_val, domains_and_openings_val) = value;

        // Allocate the commitment.
        let mut commit = builder.dyn_array::<Felt<_>>(DIGEST_SIZE);
        let commit_val: [C::F; DIGEST_SIZE] = commit_val.into();
        for (i, f) in commit_val.into_iter().enumerate() {
            builder.set(&mut commit, i, f);
        }

        let mut mats =
            builder.dyn_array::<TwoAdicPcsMatsVariable<C>>(domains_and_openings_val.len());

        for (i, (domain, openning)) in domains_and_openings_val.into_iter().enumerate() {
            let domain = builder.eval_const::<TwoAdicMultiplicativeCosetVariable<_>>(domain);

            let points_val = openning.iter().map(|(p, _)| *p).collect::<Vec<_>>();
            let values_val = openning.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>();
            let mut points: Array<_, Ext<_, _>> = builder.dyn_array(points_val.len());
            for (j, point) in points_val.into_iter().enumerate() {
                let el: Ext<_, _> = builder.eval(point.cons());
                builder.set(&mut points, j, el);
            }
            let mut values: Array<_, Array<_, Ext<_, _>>> = builder.dyn_array(values_val.len());
            for (j, val) in values_val.into_iter().enumerate() {
                let mut tmp = builder.dyn_array(val.len());
                for (k, v) in val.into_iter().enumerate() {
                    let el: Ext<_, _> = builder.eval(v.cons());
                    builder.set(&mut tmp, k, el);
                }
                builder.set(&mut values, j, tmp);
            }

            let mat = TwoAdicPcsMatsVariable {
                domain,
                points,
                values,
            };
            builder.set(&mut mats, i, mat);
        }

        Self {
            batch_commit: commit,
            mats,
        }
    }
}

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

    // Todo: change TwoAdicPcsRoundVariable to RoundVariable
    fn verify(
        &self,
        builder: &mut Builder<C>,
        rounds: Array<C, TwoAdicPcsRoundVariable<C>>,
        proof: Self::Proof,
        challenger: &mut DuplexChallengerVariable<C>,
    ) {
        verify_two_adic_pcs(builder, &self.config, rounds, proof, challenger)
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use std::cmp::Reverse;

    use crate::challenger::CanObserveVariable;
    use crate::challenger::DuplexChallengerVariable;
    use crate::challenger::FeltChallenger;
    use crate::fri::types::FriConfigVariable;
    use crate::fri::types::TwoAdicPcsRoundVariable;
    use crate::fri::TwoAdicMultiplicativeCosetVariable;
    use crate::hints::Hintable;
    use itertools::Itertools;
    use p3_challenger::CanObserve;
    use p3_challenger::FieldChallenger;
    use p3_commit::Pcs;
    use p3_commit::TwoAdicMultiplicativeCoset;
    use p3_field::AbstractField;
    use p3_field::PrimeField32;
    use p3_field::TwoAdicField;
    use p3_fri::FriConfig;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::rngs::OsRng;
    use sp1_recursion_compiler::ir::Array;
    use sp1_recursion_compiler::ir::Builder;
    use sp1_recursion_compiler::ir::Usize;
    use sp1_recursion_compiler::ir::Var;
    use sp1_recursion_compiler::InnerConfig;
    use sp1_recursion_core::runtime::Runtime;
    use sp1_recursion_core::runtime::DIGEST_SIZE;
    use sp1_recursion_core::stark::config::inner_fri_config;
    use sp1_recursion_core::stark::config::inner_perm;
    use sp1_recursion_core::stark::config::InnerChallenge;
    use sp1_recursion_core::stark::config::InnerChallengeMmcs;
    use sp1_recursion_core::stark::config::InnerChallenger;
    use sp1_recursion_core::stark::config::InnerCompress;
    use sp1_recursion_core::stark::config::InnerDft;
    use sp1_recursion_core::stark::config::InnerHash;
    use sp1_recursion_core::stark::config::InnerPcs;
    use sp1_recursion_core::stark::config::InnerPcsProof;
    use sp1_recursion_core::stark::config::InnerVal;
    use sp1_recursion_core::stark::config::InnerValMmcs;

    use crate::commit::PcsVariable;
    use crate::fri::TwoAdicFriPcsVariable;

    pub fn const_fri_config(
        builder: &mut Builder<InnerConfig>,
        config: FriConfig<InnerChallengeMmcs>,
    ) -> FriConfigVariable<InnerConfig> {
        let two_addicity = InnerVal::TWO_ADICITY;
        let mut generators = builder.dyn_array(two_addicity);
        let mut subgroups = builder.dyn_array(two_addicity);
        for i in 0..two_addicity {
            let constant_generator = InnerVal::two_adic_generator(i);
            builder.set(&mut generators, i, constant_generator);

            let constant_domain = TwoAdicMultiplicativeCoset {
                log_n: i,
                shift: InnerVal::one(),
            };
            let domain_value: TwoAdicMultiplicativeCosetVariable<_> =
                builder.eval_const(constant_domain);
            builder.set(&mut subgroups, i, domain_value);
        }
        FriConfigVariable {
            log_blowup: InnerVal::from_canonical_usize(config.log_blowup),
            num_queries: config.num_queries,
            proof_of_work_bits: config.proof_of_work_bits,
            subgroups,
            generators,
        }
    }

    #[allow(clippy::type_complexity)]
    #[test]
    fn test_two_adic_fri_pcs_single_batch() {
        let mut rng = &mut OsRng;
        let log_degrees = &[10, 16];
        let perm = inner_perm();
        let fri_config = inner_fri_config();
        let hash = InnerHash::new(perm.clone());
        let compress = InnerCompress::new(perm.clone());
        let val_mmcs = InnerValMmcs::new(hash, compress);
        let dft = InnerDft {};
        let pcs_val: InnerPcs = InnerPcs::new(
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
                    <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::natural_domain_for_degree(
                        &pcs_val,
                        1 << d,
                    ),
                    RowMajorMatrix::<InnerVal>::rand(&mut rng, 1 << d, 10 + d),
                )
            })
            .sorted_by_key(|(dom, _)| Reverse(dom.log_n))
            .collect::<Vec<_>>();
        let (commit, data) = <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::commit(
            &pcs_val,
            domains_and_polys.clone(),
        );
        let mut challenger = InnerChallenger::new(perm.clone());
        challenger.observe(commit);
        let zeta = challenger.sample_ext_element::<InnerChallenge>();
        let points = domains_and_polys
            .iter()
            .map(|_| vec![zeta])
            .collect::<Vec<_>>();
        let (opening, proof) = pcs_val.open(vec![(&data, points)], &mut challenger);

        // Verify proof.
        let mut challenger = InnerChallenger::new(perm.clone());
        challenger.observe(commit);
        challenger.sample_ext_element::<InnerChallenge>();
        let os: Vec<(
            TwoAdicMultiplicativeCoset<InnerVal>,
            Vec<(InnerChallenge, Vec<InnerChallenge>)>,
        )> = domains_and_polys
            .iter()
            .zip(&opening[0])
            .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
            .collect();
        pcs_val
            .verify(vec![(commit, os.clone())], &proof, &mut challenger)
            .unwrap();

        // Test the recursive Pcs.
        let mut builder = Builder::<InnerConfig>::default();
        let config = const_fri_config(&mut builder, inner_fri_config());
        let pcs = TwoAdicFriPcsVariable { config };
        let rounds =
            builder.eval_const::<Array<_, TwoAdicPcsRoundVariable<_>>>(vec![(commit, os.clone())]);

        // Test natural domain for degree.
        for log_d_val in log_degrees.iter() {
            let log_d: Var<_> = builder.eval(InnerVal::from_canonical_usize(*log_d_val));
            let domain = pcs.natural_domain_for_log_degree(&mut builder, Usize::Var(log_d));

            let domain_val =
                <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::natural_domain_for_degree(
                    &pcs_val,
                    1 << log_d_val,
                );

            let expected_domain: TwoAdicMultiplicativeCosetVariable<_> =
                builder.eval_const(domain_val);

            builder.assert_eq::<TwoAdicMultiplicativeCosetVariable<_>>(domain, expected_domain);
        }

        // Test proof verification.
        let proofvar = InnerPcsProof::read(&mut builder);
        let mut challenger = DuplexChallengerVariable::new(&mut builder);
        let commit = <[InnerVal; DIGEST_SIZE]>::from(commit).to_vec();
        let commit = builder.eval_const::<Array<_, _>>(commit);
        challenger.observe(&mut builder, commit);
        challenger.sample_ext(&mut builder);
        pcs.verify(&mut builder, rounds, proofvar, &mut challenger);

        let program = builder.compile();
        let mut runtime = Runtime::<InnerVal, InnerChallenge, _>::new(&program, perm.clone());
        runtime.witness_stream.extend(proof.write());
        runtime.run();
        println!(
            "The program executed successfully, number of cycles: {}",
            runtime.clk.as_canonical_u32() / 4
        );
    }

    #[allow(clippy::type_complexity)]
    #[test]
    fn test_two_adic_fri_pcs_multi_batches() {
        let mut rng = &mut OsRng;
        let log_degrees = &[10, 16];
        let perm = inner_perm();
        let fri_config = inner_fri_config();
        let hash = InnerHash::new(perm.clone());
        let compress = InnerCompress::new(perm.clone());
        let val_mmcs = InnerValMmcs::new(hash, compress);
        let dft = InnerDft {};
        let pcs_val: InnerPcs = InnerPcs::new(
            log_degrees.iter().copied().max().unwrap(),
            dft,
            val_mmcs,
            fri_config,
        );

        // Generate proof.
        let num_of_batches = 3;

        let mut batch_domains_and_polys = vec![];
        let mut batches_commits = vec![];
        let mut batches_prover_data = vec![];

        for _ in 0..num_of_batches {
            let domains_and_polys = log_degrees
                .iter()
                .map(|&d| {
                    (
                        <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::natural_domain_for_degree(
                            &pcs_val,
                            1 << d,
                        ),
                        RowMajorMatrix::<InnerVal>::rand(&mut rng, 1 << d, 10 + d),
                    )
                })
                .sorted_by_key(|(dom, _)| Reverse(dom.log_n))
                .collect::<Vec<_>>();
            let (commit, data) = <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::commit(
                &pcs_val,
                domains_and_polys.clone(),
            );

            batch_domains_and_polys.push(domains_and_polys);
            batches_commits.push(commit);
            batches_prover_data.push(data);
        }

        let mut challenger = InnerChallenger::new(perm.clone());
        for commit in batches_commits.iter() {
            challenger.observe(*commit);
        }

        let zeta = challenger.sample_ext_element::<InnerChallenge>();
        let points = log_degrees.iter().map(|_| vec![zeta]).collect::<Vec<_>>();

        let data_and_points = batches_prover_data
            .iter()
            .map(|data| (data, points.clone()))
            .collect::<Vec<_>>();
        let (opening, proof) = pcs_val.open(data_and_points, &mut challenger);

        // Verify proof.
        let mut challenger = InnerChallenger::new(perm.clone());
        for commit in batches_commits.iter() {
            challenger.observe(*commit);
        }
        challenger.sample_ext_element::<InnerChallenge>();

        let rounds_val = batches_commits
            .clone()
            .into_iter()
            .zip(batch_domains_and_polys)
            .zip(opening)
            .map(|((commit, domains_and_polys), open_vals)| {
                let os = domains_and_polys
                    .iter()
                    .zip(open_vals)
                    .map(|((domain, _), mat_openings)| {
                        (*domain, vec![(zeta, mat_openings[0].clone())])
                    })
                    .collect();
                (commit, os)
            })
            .collect::<Vec<_>>();

        pcs_val
            .verify(rounds_val.clone(), &proof, &mut challenger)
            .unwrap();

        // Test the recursive Pcs.
        let mut builder = Builder::<InnerConfig>::default();
        let config = const_fri_config(&mut builder, inner_fri_config());
        let pcs = TwoAdicFriPcsVariable { config };
        let rounds = builder.eval_const::<Array<_, TwoAdicPcsRoundVariable<_>>>(rounds_val);

        // // Test proof verification.
        let proofvar = InnerPcsProof::read(&mut builder);
        let mut challenger = DuplexChallengerVariable::new(&mut builder);
        for commit in batches_commits {
            let commit: [InnerVal; DIGEST_SIZE] = commit.into();
            let commit = builder.eval_const::<Array<_, _>>(commit.to_vec());
            challenger.observe(&mut builder, commit);
        }
        challenger.sample_ext(&mut builder);
        pcs.verify(&mut builder, rounds, proofvar, &mut challenger);

        let program = builder.compile();
        let mut runtime = Runtime::<InnerVal, InnerChallenge, _>::new(&program, perm.clone());
        runtime.witness_stream.extend(proof.write());
        runtime.run();
        println!(
            "The program executed successfully, number of cycles: {}",
            runtime.clk.as_canonical_u32() / 4
        );
    }
}
