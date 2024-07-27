use itertools::{izip, Itertools};
use p3_commit::PolynomialSpace;
use p3_field::{AbstractField, TwoAdicField};
use p3_fri::FriConfig;
use p3_matrix::Dimensions;
use p3_util::log2_strict_usize;
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, CircuitV2FriFoldInput, CircuitV2FriFoldOutput, Config, Felt, SymbolicExt},
};
use std::{
    cmp::Reverse,
    iter::{repeat_with, zip},
    mem::take,
};

use crate::challenger::DuplexChallengerVariable;
use crate::*;

pub fn verify_shape_and_sample_challenges<C: Config, Mmcs>(
    builder: &mut Builder<C>,
    config: &FriConfig<Mmcs>,
    proof: &FriProofVariable<C>,
    challenger: &mut DuplexChallengerVariable<C>,
) -> FriChallenges<C> {
    let betas = proof
        .commit_phase_commits
        .iter()
        .map(|&commitment| {
            challenger.observe_commitment(builder, commitment);
            challenger.sample_ext(builder)
        })
        .collect();

    // Observe the final polynomial.
    let final_poly_felts = builder.ext2felt_circuit(proof.final_poly);
    final_poly_felts.iter().for_each(|felt| {
        challenger.observe(builder, *felt);
    });

    assert_eq!(proof.query_proofs.len(), config.num_queries);
    challenger.check_witness(builder, config.proof_of_work_bits, proof.pow_witness);

    let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;
    let query_indices: Vec<Vec<Felt<_>>> =
        repeat_with(|| challenger.sample_bits(builder, log_max_height))
            .take(config.num_queries)
            .collect();

    FriChallenges {
        query_indices,
        betas,
    }
}

pub fn verify_two_adic_pcs<C: Config, Mmcs>(
    builder: &mut Builder<C>,
    config: &FriConfig<Mmcs>,
    proof: &TwoAdicPcsProofVariable<C>,
    challenger: &mut DuplexChallengerVariable<C>,
    rounds: Vec<TwoAdicPcsRoundVariable<C>>,
) {
    let alpha = challenger.sample_ext(builder);

    let fri_challenges =
        verify_shape_and_sample_challenges(builder, config, &proof.fri_proof, challenger);

    let log_global_max_height = proof.fri_proof.commit_phase_commits.len() + config.log_blowup;

    // The powers of alpha, where the ith element is alpha^i.
    let mut alpha_pows: Vec<Ext<C::F, C::EF>> =
        vec![builder.eval(SymbolicExt::from_f(C::EF::one()))];

    let reduced_openings = proof
        .query_openings
        .iter()
        .zip(&fri_challenges.query_indices)
        .map(|(query_opening, index_bits)| {
            let mut ro: [Ext<C::F, C::EF>; 32] =
                [builder.eval(SymbolicExt::from_f(C::EF::zero())); 32];

            for (batch_opening, round) in izip!(query_opening, rounds.clone()) {
                let batch_commit = round.batch_commit;
                let mats = round.mats;
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
                    let mat_domain = mat.domain;
                    let mat_points = mat.points;
                    let mat_values = mat.values;
                    let log_height = log2_strict_usize(mat_domain.size()) + config.log_blowup;

                    let bits_reduced = log_global_max_height - log_height;
                    let reduced_index_bits_trunc =
                        index_bits[bits_reduced..(bits_reduced + log_height)].to_vec();

                    let g = builder.generator();
                    let two_adic_generator: Felt<_> =
                        builder.eval(C::F::two_adic_generator(log_height));
                    let two_adic_generator_exp =
                        builder.exp_reverse_bits_v2(two_adic_generator, reduced_index_bits_trunc);
                    let x: Felt<_> = builder.eval(g * two_adic_generator_exp);

                    for (z, ps_at_z) in izip!(mat_points, mat_values) {
                        let CircuitV2FriFoldOutput {
                            alpha_pow_output,
                            ro_output,
                        } = builder.fri_fold_v2(CircuitV2FriFoldInput {
                            z,
                            alpha,
                            x,
                            mat_opening: mat_opening.clone(),
                            ps_at_z,
                            alpha_pow_input: take(&mut alpha_pows),
                            ro_input: ro.to_vec(),
                        });
                        alpha_pows = alpha_pow_output;

                        ro = ro_output.try_into().unwrap();
                    }
                }
            }
            ro
        })
        .collect::<Vec<_>>();

    verify_challenges(
        builder,
        config,
        &proof.fri_proof,
        &fri_challenges,
        reduced_openings,
    );
}

pub fn verify_challenges<C: Config, Mmcs>(
    builder: &mut Builder<C>,
    config: &FriConfig<Mmcs>,
    proof: &FriProofVariable<C>,
    challenges: &FriChallenges<C>,
    reduced_openings: Vec<[Ext<C::F, C::EF>; 32]>,
) {
    let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;
    for (index_bits, query_proof, ro) in izip!(
        &challenges.query_indices,
        &proof.query_proofs,
        reduced_openings
    ) {
        let folded_eval = verify_query(
            builder,
            proof.commit_phase_commits.clone(),
            index_bits,
            query_proof.clone(),
            challenges.betas.clone(),
            ro,
            log_max_height,
        );

        builder.assert_ext_eq(folded_eval, proof.final_poly);
    }
}

pub fn verify_query<C: Config>(
    builder: &mut Builder<C>,
    commit_phase_commits: Vec<DigestVariable<C>>,
    index_bits: &[Felt<C::F>],
    proof: FriQueryProofVariable<C>,
    betas: Vec<Ext<C::F, C::EF>>,
    reduced_openings: [Ext<C::F, C::EF>; 32],
    log_max_height: usize,
) -> Ext<C::F, C::EF> {
    let mut folded_eval: Ext<_, _> = builder.eval(SymbolicExt::from_f(C::EF::zero()));
    let two_adic_generator: Felt<_> = builder.eval(C::F::two_adic_generator(log_max_height));
    index_bits
        .iter()
        .for_each(|&bit| builder.assert_felt_eq(bit * bit, bit)); // Is this line needed?
    let mut x = builder.exp_reverse_bits_v2(two_adic_generator, index_bits.to_vec());

    for (offset, (log_folded_height, commit, step, beta)) in izip!(
        (0..log_max_height).rev(),
        commit_phase_commits,
        &proof.commit_phase_openings,
        betas,
    )
    .enumerate()
    {
        folded_eval = builder.eval(folded_eval + reduced_openings[log_folded_height + 1]);

        let one: Felt<_> = builder.eval(C::F::one());
        let index_sibling: Felt<_> = builder.eval(one - index_bits[offset]);
        let index_pair = &index_bits[(offset + 1)..];

        let evals_ext = {
            // TODO factor this out into a function
            let bit = index_sibling;
            let true_fst = folded_eval;
            let true_snd = step.sibling_value;

            let one: Felt<_> = builder.eval(C::F::one());
            let cobit: Felt<_> = builder.eval(one - bit);

            let true_branch = [true_fst, true_snd];
            let false_branch = [true_snd, true_fst];
            zip(true_branch, false_branch)
                .map(|(tx, fx)| builder.eval(tx * bit + fx * cobit))
                .collect::<Vec<_>>()
        };

        let dims = &[Dimensions {
            width: 2,
            height: (1 << log_folded_height),
        }];
        verify_batch::<C, 4>(
            builder,
            commit,
            dims.to_vec(),
            index_pair.to_vec(),
            [evals_ext.clone()].to_vec(),
            step.opening_proof.clone(),
        );

        let xs_new: Felt<_> = builder.eval(x * C::F::two_adic_generator(1));
        let xs: Vec<Felt<C::F>> = {
            // TODO factor this out into a function
            let bit = index_sibling;
            let true_fst = x;
            let true_snd = xs_new;

            let one: Felt<_> = builder.eval(C::F::one());
            let cobit: Felt<_> = builder.eval(one - bit);

            let true_branch = [true_fst, true_snd];
            let false_branch = [true_snd, true_fst];
            zip(true_branch, false_branch)
                .map(|(tx, fx)| builder.eval(tx * bit + fx * cobit))
                .collect::<Vec<_>>()
        };
        folded_eval = builder
            .eval(evals_ext[0] + (beta - xs[0]) * (evals_ext[1] - evals_ext[0]) / (xs[1] - xs[0]));
        x = builder.eval(x * x);
    }

    folded_eval
}

pub fn verify_batch<C: Config, const D: usize>(
    builder: &mut Builder<C>,
    commit: DigestVariable<C>,
    dimensions: Vec<Dimensions>,
    index_bits: Vec<Felt<C::F>>,
    opened_values: Vec<Vec<Ext<C::F, C::EF>>>,
    proof: Vec<DigestVariable<C>>,
) {
    let opened_values = opened_values
        .into_iter()
        .map(|value| {
            value
                .into_iter()
                .map(|ext| builder.ext2felt_v2(ext))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut heights_tallest_first = dimensions
        .iter()
        .enumerate()
        .sorted_by_key(|(_, dims)| Reverse(dims.height))
        .peekable();

    let mut curr_height_padded = heights_tallest_first
        .peek()
        .unwrap()
        .1
        .height
        .next_power_of_two();

    let felt_slice: Vec<Felt<C::F>> = heights_tallest_first
        .peeking_take_while(|(_, dims)| dims.height.next_power_of_two() == curr_height_padded)
        .flat_map(|(i, _)| opened_values[i].as_slice())
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    let mut root = builder.poseidon2_hash_v2(&felt_slice);

    for (bit, sibling) in zip(index_bits, proof) {
        let one: Felt<_> = builder.eval(C::F::one());
        let cobit: Felt<_> = builder.eval(one - bit);

        let true_branch = sibling.into_iter().chain(root);
        let false_branch = root.into_iter().chain(sibling);
        let pre_root = zip(true_branch, false_branch)
            .map(|(tx, fx)| builder.eval(bit * tx + cobit * fx))
            .collect::<Vec<_>>();

        root = builder.poseidon2_compress_v2(pre_root);
        curr_height_padded >>= 1;

        let next_height = heights_tallest_first
            .peek()
            .map(|(_, dims)| dims.height)
            .filter(|h| h.next_power_of_two() == curr_height_padded);

        if let Some(next_height) = next_height {
            let felt_slice: Vec<Felt<C::F>> = heights_tallest_first
                .peeking_take_while(|(_, dims)| dims.height == next_height)
                .flat_map(|(i, _)| opened_values[i].as_slice())
                .flatten()
                .cloned()
                .collect::<Vec<_>>();
            let next_height_openings_digest = builder.poseidon2_hash_v2(&felt_slice);
            root =
                builder.poseidon2_compress_v2(root.into_iter().chain(next_height_openings_digest));
        }
    }

    zip(root, commit).for_each(|(e1, e2)| {
        builder.print_f(e1);
        builder.print_f(e2);
    });
    zip(root, commit).for_each(|(e1, e2)| builder.assert_felt_eq(e1, e2));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::tests::run_test_recursion;
    use crate::challenger::DuplexChallengerVariable;
    use crate::{
        BatchOpeningVariable, DigestVariable, FriCommitPhaseProofStepVariable, FriProofVariable,
        FriQueryProofVariable, TwoAdicPcsMatsVariable, TwoAdicPcsProofVariable, DIGEST_SIZE,
    };
    use p3_challenger::FieldChallenger;
    use p3_challenger::{CanObserve, CanSample};
    use p3_commit::{Pcs, TwoAdicMultiplicativeCoset};
    use p3_field::AbstractField;
    use p3_fri::{verifier, TwoAdicFriPcsProof};
    use p3_matrix::dense::RowMajorMatrix;
    use rand::rngs::OsRng;
    use sp1_core::stark::StarkGenericConfig;
    use sp1_core::utils::baby_bear_poseidon2::compressed_fri_config;
    use sp1_core::utils::{
        inner_perm, BabyBearPoseidon2, InnerChallenge, InnerChallengeMmcs, InnerChallenger,
        InnerCompress, InnerDft, InnerFriProof, InnerHash, InnerPcs, InnerVal, InnerValMmcs,
    };
    use sp1_recursion_compiler::asm::AsmBuilder;
    use sp1_recursion_compiler::config::InnerConfig;
    use sp1_recursion_compiler::ir::Ext;
    use sp1_recursion_compiler::ir::{Builder, SymbolicExt};

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    pub fn const_fri_proof(
        builder: &mut AsmBuilder<F, EF>,
        fri_proof: InnerFriProof,
    ) -> FriProofVariable<InnerConfig> {
        // Set the commit phase commits.
        let commit_phase_commits = fri_proof
            .commit_phase_commits
            .iter()
            .map(|commit| {
                let commit: [F; DIGEST_SIZE] = (*commit).into();
                commit.map(|x| builder.eval(x))
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
                            builder.eval(SymbolicExt::from_f(commit_phase_opening.sibling_value));
                        let opening_proof = commit_phase_opening
                            .opening_proof
                            .iter()
                            .map(|sibling| sibling.map(|x| builder.eval(x)))
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
            final_poly: builder.eval(SymbolicExt::from_f(fri_proof.final_poly)),
            pow_witness: builder.eval(fri_proof.pow_witness),
        }
    }

    pub fn const_two_adic_pcs_proof(
        builder: &mut Builder<InnerConfig>,
        proof: TwoAdicFriPcsProof<InnerVal, InnerChallenge, InnerValMmcs, InnerChallengeMmcs>,
    ) -> TwoAdicPcsProofVariable<InnerConfig> {
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
                                    .map(|value| builder.eval(*value))
                                    .collect::<Vec<_>>()
                            })
                            .collect::<Vec<_>>(),
                        opening_proof: opening
                            .opening_proof
                            .iter()
                            .map(|opening_proof| opening_proof.map(|x| builder.eval(x)))
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

    #[allow(clippy::type_complexity)]
    pub fn const_two_adic_pcs_rounds(
        builder: &mut Builder<InnerConfig>,
        commit: [F; DIGEST_SIZE],
        os: Vec<(
            TwoAdicMultiplicativeCoset<InnerVal>,
            Vec<(InnerChallenge, Vec<InnerChallenge>)>,
        )>,
    ) -> (
        DigestVariable<InnerConfig>,
        Vec<TwoAdicPcsRoundVariable<InnerConfig>>,
    ) {
        let commit: DigestVariable<InnerConfig> = commit.map(|x| builder.eval(x));

        let mut mats = Vec::new();
        for (domain, poly) in os.into_iter() {
            let points: Vec<Ext<InnerVal, InnerChallenge>> = poly
                .iter()
                .map(|(p, _)| builder.eval(SymbolicExt::from_f(*p)))
                .collect::<Vec<_>>();
            let values: Vec<Vec<Ext<InnerVal, InnerChallenge>>> = poly
                .iter()
                .map(|(_, v)| {
                    v.clone()
                        .iter()
                        .map(|t| builder.eval(SymbolicExt::from_f(*t)))
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
    fn test_fri_verify_shape_and_sample_challenges() {
        let mut rng = &mut OsRng;
        let log_degrees = &[16, 9, 7, 4, 2];
        let perm = inner_perm();
        let fri_config = compressed_fri_config();
        let hash = InnerHash::new(perm.clone());
        let compress = InnerCompress::new(perm.clone());
        let val_mmcs = InnerValMmcs::new(hash, compress);
        let dft = InnerDft {};
        let pcs: InnerPcs = InnerPcs::new(
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
                        &pcs,
                        1 << d,
                    ),
                    RowMajorMatrix::<InnerVal>::rand(&mut rng, 1 << d, 10),
                )
            })
            .collect::<Vec<_>>();
        let (commit, data) = <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::commit(
            &pcs,
            domains_and_polys.clone(),
        );
        let mut challenger = InnerChallenger::new(perm.clone());
        challenger.observe(commit);
        let zeta = challenger.sample_ext_element::<InnerChallenge>();
        let points = domains_and_polys
            .iter()
            .map(|_| vec![zeta])
            .collect::<Vec<_>>();
        let (_, proof) = pcs.open(vec![(&data, points)], &mut challenger);

        // Verify proof.
        let mut challenger = InnerChallenger::new(perm.clone());
        challenger.observe(commit);
        let _: InnerChallenge = challenger.sample();
        let fri_challenges_gt = verifier::verify_shape_and_sample_challenges(
            &compressed_fri_config(),
            &proof.fri_proof,
            &mut challenger,
        )
        .unwrap();

        // Define circuit.
        let mut builder = Builder::<InnerConfig>::default();
        let config = compressed_fri_config();
        let fri_proof = const_fri_proof(&mut builder, proof.fri_proof);

        let mut challenger = DuplexChallengerVariable::new(&mut builder);
        let commit: [_; DIGEST_SIZE] = commit.into();
        let commit = commit.map(|x| builder.eval(x));
        challenger.observe_commitment(&mut builder, commit);
        let _ = challenger.sample_ext(&mut builder);
        let fri_challenges =
            verify_shape_and_sample_challenges(&mut builder, &config, &fri_proof, &mut challenger);

        for i in 0..fri_challenges_gt.betas.len() {
            builder.assert_ext_eq(
                SymbolicExt::from_f(fri_challenges_gt.betas[i]),
                fri_challenges.betas[i],
            );
        }

        for i in 0..fri_challenges_gt.query_indices.len() {
            let query_indices =
                builder.bits2num_v2_f(fri_challenges.query_indices[i].iter().cloned());
            builder.assert_felt_eq(
                F::from_canonical_usize(fri_challenges_gt.query_indices[i]),
                query_indices,
            );
        }

        run_test_recursion(builder.operations);
    }

    #[test]
    fn test_verify_two_adic_pcs() {
        let mut rng = &mut OsRng;
        let log_degrees = &[19, 19];
        let perm = inner_perm();
        let fri_config = compressed_fri_config();
        let hash = InnerHash::new(perm.clone());
        let compress = InnerCompress::new(perm.clone());
        let val_mmcs = InnerValMmcs::new(hash, compress);
        let dft = InnerDft {};
        let pcs: InnerPcs = InnerPcs::new(
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
                        &pcs,
                        1 << d,
                    ),
                    RowMajorMatrix::<InnerVal>::rand(&mut rng, 1 << d, 100),
                )
            })
            .collect::<Vec<_>>();
        let (commit, data) = <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::commit(
            &pcs,
            domains_and_polys.clone(),
        );
        let mut challenger = InnerChallenger::new(perm.clone());
        challenger.observe(commit);
        let zeta = challenger.sample_ext_element::<InnerChallenge>();
        let points = domains_and_polys
            .iter()
            .map(|_| vec![zeta])
            .collect::<Vec<_>>();
        let (opening, proof) = pcs.open(vec![(&data, points)], &mut challenger);

        // Verify proof.
        let mut challenger = InnerChallenger::new(perm.clone());
        challenger.observe(commit);
        challenger.sample_ext_element::<InnerChallenge>();
        let os = domains_and_polys
            .iter()
            .zip(&opening[0])
            .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
            .collect::<Vec<_>>();
        pcs.verify(vec![(commit, os.clone())], &proof, &mut challenger)
            .unwrap();

        // Define circuit.
        let mut builder = Builder::<InnerConfig>::default();
        let config = compressed_fri_config();
        let proof = const_two_adic_pcs_proof(&mut builder, proof);
        let (commit, rounds) = const_two_adic_pcs_rounds(&mut builder, commit.into(), os);
        let mut challenger = DuplexChallengerVariable::new(&mut builder);
        challenger.observe_commitment(&mut builder, commit);
        challenger.sample_ext(&mut builder);
        verify_two_adic_pcs(&mut builder, &config, &proof, &mut challenger, rounds);

        run_test_recursion(builder.operations);
        // let mut backend = ConstraintCompiler::<InnerConfig>::default();
        // let constraints = backend.emit(builder.operations);
        // PlonkBn254Prover::test::<InnerConfig>(constraints.clone(), Witness::default());
    }
}
