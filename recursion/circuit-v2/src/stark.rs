use hashbrown::HashMap;
use itertools::Itertools;
use p3_commit::Mmcs;
use p3_matrix::dense::RowMajorMatrix;

use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_commit::Pcs;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::TwoAdicField;

use p3_commit::PolynomialSpace;
use sp1_core::air::MachineAir;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::stark::StarkMachine;
use sp1_core::stark::Val;
use sp1_core::stark::{AirOpenedValues, ChipOpenedValues};

use sp1_core::stark::StarkVerifyingKey;
use sp1_recursion_compiler::ir::{Builder, Config, Ext, ExtConst, FromConstant};
use sp1_recursion_compiler::prelude::Felt;

use crate::BabyBearFriConfigVariable;
use crate::DigestVariable;
use crate::TwoAdicPcsMatsVariable;
use crate::TwoAdicPcsProofVariable;

use crate::challenger::CanObserveVariable;
use crate::challenger::FeltChallenger;
use crate::constraints::RecursiveVerifierConstraintFolder;
use crate::domain::PolynomialSpaceVariable;
use crate::fri::verify_two_adic_pcs;
use crate::TwoAdicPcsRoundVariable;
use crate::VerifyingKeyVariable;

/// Reference: [sp1_core::stark::ShardProof]
#[derive(Clone)]
pub struct ShardProofVariable<C: Config> {
    pub commitment: ShardCommitmentVariable<C>,
    pub opened_values: ShardOpenedValuesVariable<C>,
    pub opening_proof: TwoAdicPcsProofVariable<C>,
    pub chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<Felt<C::F>>,
}

/// Reference: [sp1_core::stark::ShardCommitment]
#[derive(Debug, Clone)]
pub struct ShardCommitmentVariable<C: Config> {
    pub main_commit: DigestVariable<C>,
    pub permutation_commit: DigestVariable<C>,
    pub quotient_commit: DigestVariable<C>,
}

/// Reference: [sp1_core::stark::ShardOpenedValues]
#[derive(Debug, Clone)]
pub struct ShardOpenedValuesVariable<C: Config> {
    pub chips: Vec<ChipOpenedValuesVariable<C>>,
}

#[derive(Debug, Clone)]
pub struct ChipOpenedValuesVariable<C: Config> {
    pub preprocessed: AirOpenedValuesVariable<C>,
    pub main: AirOpenedValuesVariable<C>,
    pub permutation: AirOpenedValuesVariable<C>,
    pub quotient: Vec<Vec<Ext<C::F, C::EF>>>,
    pub cumulative_sum: Ext<C::F, C::EF>,
    pub log_degree: usize,
}

#[derive(Debug, Clone)]
pub struct AirOpenedValuesVariable<C: Config> {
    pub local: Vec<Ext<C::F, C::EF>>,
    pub next: Vec<Ext<C::F, C::EF>>,
}

impl<C: Config> FromConstant<C> for AirOpenedValuesVariable<C> {
    type Constant = AirOpenedValues<C::EF>;

    fn constant(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        AirOpenedValuesVariable {
            local: value.local.iter().map(|x| builder.constant(*x)).collect(),
            next: value.next.iter().map(|x| builder.constant(*x)).collect(),
        }
    }
}

impl<C: Config> FromConstant<C> for ChipOpenedValuesVariable<C> {
    type Constant = ChipOpenedValues<C::EF>;

    fn constant(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        ChipOpenedValuesVariable {
            preprocessed: builder.constant(value.preprocessed),
            main: builder.constant(value.main),
            permutation: builder.constant(value.permutation),
            quotient: value
                .quotient
                .iter()
                .map(|x| x.iter().map(|y| builder.constant(*y)).collect())
                .collect(),
            cumulative_sum: builder.eval(value.cumulative_sum.cons()),
            log_degree: value.log_degree,
        }
    }
}

pub const EMPTY: usize = 0x_1111_1111;

#[derive(Debug, Clone, Copy)]
pub struct StarkVerifier<C: Config, SC: StarkGenericConfig> {
    _phantom: std::marker::PhantomData<(C, SC)>,
}

pub struct VerifyingKeyHint<'a, SC: StarkGenericConfig, A> {
    pub machine: &'a StarkMachine<SC, A>,
    pub vk: &'a StarkVerifyingKey<SC>,
}

impl<'a, SC: StarkGenericConfig, A: MachineAir<SC::Val>> VerifyingKeyHint<'a, SC, A> {
    pub const fn new(machine: &'a StarkMachine<SC, A>, vk: &'a StarkVerifyingKey<SC>) -> Self {
        Self { machine, vk }
    }
}

impl<C, SC> StarkVerifier<C, SC>
where
    C::F: TwoAdicField,
    SC: BabyBearFriConfigVariable<C = C>,
    C: Config<F = SC::Val>,
    <SC::ValMmcs as Mmcs<BabyBear>>::ProverData<RowMajorMatrix<BabyBear>>: Clone,
{
    pub fn natural_domain_for_degree(
        config: &SC,
        degree: usize,
    ) -> TwoAdicMultiplicativeCoset<C::F> {
        <SC::Pcs as Pcs<SC::Challenge, SC::FriChallenger>>::natural_domain_for_degree(
            config.pcs(),
            degree,
        )
    }

    pub fn verify_shard<A>(
        builder: &mut Builder<C>,
        vk: &VerifyingKeyVariable<C>,
        machine: &StarkMachine<SC, A>,
        challenger: &mut SC::FriChallengerVariable,
        proof: &ShardProofVariable<C>,
    ) where
        A: MachineAir<Val<SC>> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
    {
        builder.cycle_tracker("stage-c-verify-shard-setup");

        let chips = machine
            .shard_chips_ordered(&proof.chip_ordering)
            .collect::<Vec<_>>();

        let ShardProofVariable {
            commitment,
            opened_values,
            opening_proof,
            chip_ordering,
            public_values: _,
        } = proof;

        let log_degrees = opened_values
            .chips
            .iter()
            .map(|val| val.log_degree)
            .collect::<Vec<_>>();

        let log_quotient_degrees = chips
            .iter()
            .map(|chip| chip.log_quotient_degree())
            .collect::<Vec<_>>();

        let trace_domains = log_degrees
            .iter()
            .map(|log_degree| Self::natural_domain_for_degree(machine.config(), 1 << log_degree))
            .collect::<Vec<_>>();

        let ShardCommitmentVariable {
            main_commit,
            permutation_commit,
            quotient_commit,
        } = commitment;

        let _permutation_challenges = (0..2)
            .map(|_| challenger.sample_ext(builder))
            .collect::<Vec<_>>();

        challenger.observe_slice(builder, *permutation_commit);

        let _alpha = challenger.sample_ext(builder);

        challenger.observe_slice(builder, *quotient_commit);

        let zeta = challenger.sample_ext(builder);

        let preprocessed_domains_points_and_opens = vk
            .chip_information
            .iter()
            .map(|(name, domain, _)| {
                let i = chip_ordering[name];
                let values = opened_values.chips[i].preprocessed.clone();
                TwoAdicPcsMatsVariable::<C> {
                    domain: *domain,
                    points: vec![zeta, domain.next_point_variable(builder, zeta)],
                    values: vec![values.local, values.next],
                }
            })
            .collect::<Vec<_>>();

        let main_domains_points_and_opens = trace_domains
            .iter()
            .zip_eq(opened_values.chips.iter())
            .map(|(domain, values)| TwoAdicPcsMatsVariable::<C> {
                domain: *domain,
                points: vec![zeta, domain.next_point_variable(builder, zeta)],
                values: vec![values.main.local.clone(), values.main.next.clone()],
            })
            .collect::<Vec<_>>();

        let perm_domains_points_and_opens = trace_domains
            .iter()
            .zip_eq(opened_values.chips.iter())
            .map(|(domain, values)| TwoAdicPcsMatsVariable::<C> {
                domain: *domain,
                points: vec![zeta, domain.next_point_variable(builder, zeta)],
                values: vec![
                    values.permutation.local.clone(),
                    values.permutation.next.clone(),
                ],
            })
            .collect::<Vec<_>>();

        let quotient_chunk_domains = trace_domains
            .iter()
            .zip_eq(log_degrees)
            .zip_eq(log_quotient_degrees)
            .map(|((domain, log_degree), log_quotient_degree)| {
                let quotient_degree = 1 << log_quotient_degree;
                let quotient_domain =
                    domain.create_disjoint_domain(1 << (log_degree + log_quotient_degree));
                quotient_domain.split_domains(quotient_degree)
            })
            .collect::<Vec<_>>();

        let quotient_domains_points_and_opens = proof
            .opened_values
            .chips
            .iter()
            .zip_eq(quotient_chunk_domains.iter())
            .flat_map(|(values, qc_domains)| {
                values
                    .quotient
                    .iter()
                    .zip_eq(qc_domains)
                    .map(move |(values, q_domain)| TwoAdicPcsMatsVariable::<C> {
                        domain: *q_domain,
                        points: vec![zeta],
                        values: vec![values.clone()],
                    })
            })
            .collect::<Vec<_>>();

        // let num_shard_chips = opened_values.chips.len();
        // let mut trace_domains = Vec::new();
        // let mut quotient_domains = Vec::new();

        // let mut main_mats: Vec<TwoAdicPcsMatsVariable<_>> = Vec::new();
        // let mut perm_mats: Vec<TwoAdicPcsMatsVariable<_>> = Vec::new();

        // let mut quotient_mats = Vec::new();

        // let qc_points = vec![zeta];

        // // Iterate through machine.chips filtered for preprocessed chips.
        // let prep_mats: Vec<TwoAdicPcsMatsVariable<_>> = {
        //     let mut ms = zip(
        //         &vk.preprocessed_sorted_idxs,
        //         zip(&vk.prep_domains, machine.preprocessed_chip_ids()).map(
        //             |(&domain, chip_id): (&TwoAdicMultiplicativeCoset<_>, usize)| {
        //                 // Get index within all sorted chips.
        //                 let chip_sorted_id = proof.sorted_idxs[chip_id];
        //                 // Get opening from proof.
        //                 let opening = &opened_values.chips[chip_sorted_id];

        //                 let domain_var: TwoAdicMultiplicativeCosetVariable<_> =
        //                     builder.constant(domain);

        //                 let zeta_next = domain_var.next_point(builder, zeta);
        //                 let trace_points = vec![zeta, zeta_next];

        //                 let prep_values = vec![
        //                     opening.preprocessed.local.clone(),
        //                     opening.preprocessed.next.clone(),
        //                 ];

        //                 TwoAdicPcsMatsVariable::<C> {
        //                     domain,
        //                     values: prep_values,
        //                     points: trace_points,
        //                 }
        //             },
        //         ),
        //     )
        //     .collect::<Vec<_>>();
        //     // Invert the `vk.preprocessed_sorted_idxs` permutation.
        //     ms.sort_unstable_by_key(|(x, _)| *x);
        //     ms.into_iter().map(|(_, y)| y).collect::<Vec<_>>()
        // };

        // (0..num_shard_chips).for_each(|i| {
        //     let opening = &opened_values.chips[i];
        //     let log_quotient_degree = proof.quotient_data[i].log_quotient_degree;
        //     let domain = new_coset(builder, opening.log_degree);

        //     let log_quotient_size = opening.log_degree + log_quotient_degree;
        //     let quotient_domain =
        //         domain.create_disjoint_domain(builder, Usize::Const(log_quotient_size), None);

        //     let mut trace_points = Vec::new();
        //     let zeta_next = domain.next_point(builder, zeta);
        //     trace_points.push(zeta);
        //     trace_points.push(zeta_next);

        //     let main_values = vec![opening.main.local.clone(), opening.main.next.clone()];
        //     let main_mat = TwoAdicPcsMatsVariable::<C> {
        //         domain: TwoAdicMultiplicativeCoset {
        //             log_n: domain.log_n,
        //             shift: domain.shift,
        //         },
        //         values: main_values,
        //         points: trace_points.clone(),
        //     };

        //     let perm_values = vec![
        //         opening.permutation.local.clone(),
        //         opening.permutation.next.clone(),
        //     ];
        //     let perm_mat = TwoAdicPcsMatsVariable::<C> {
        //         domain: TwoAdicMultiplicativeCoset {
        //             log_n: domain.clone().log_n,
        //             shift: domain.clone().shift,
        //         },
        //         values: perm_values,
        //         points: trace_points,
        //     };

        //     let qc_mats = quotient_domain
        //         .split_domains_const(builder, log_quotient_degree)
        //         .into_iter()
        //         .enumerate()
        //         .map(|(j, qc_dom)| TwoAdicPcsMatsVariable::<C> {
        //             domain: TwoAdicMultiplicativeCoset {
        //                 log_n: qc_dom.clone().log_n,
        //                 shift: qc_dom.clone().shift,
        //             },
        //             values: vec![opening.quotient[j].clone()],
        //             points: qc_points.clone(),
        //         });

        //     trace_domains.push(domain.clone());
        //     quotient_domains.push(quotient_domain.clone());
        //     main_mats.push(main_mat);
        //     perm_mats.push(perm_mat);
        //     quotient_mats.extend(qc_mats);
        // });

        // Create the pcs rounds.
        let prep_commit = vk.commitment;
        let prep_round = TwoAdicPcsRoundVariable {
            batch_commit: prep_commit,
            domains_points_and_opens: preprocessed_domains_points_and_opens,
        };
        let main_round = TwoAdicPcsRoundVariable {
            batch_commit: *main_commit,
            domains_points_and_opens: main_domains_points_and_opens,
        };
        let perm_round = TwoAdicPcsRoundVariable {
            batch_commit: *permutation_commit,
            domains_points_and_opens: perm_domains_points_and_opens,
        };
        let quotient_round = TwoAdicPcsRoundVariable {
            batch_commit: *quotient_commit,
            domains_points_and_opens: quotient_domains_points_and_opens,
        };
        let rounds = vec![prep_round, main_round, perm_round, quotient_round];
        // builder.cycle_tracker("stage-c-verify-shard-setup");

        // Verify the pcs proof
        builder.cycle_tracker("stage-d-verify-pcs");
        let config = machine.config().fri_config();
        verify_two_adic_pcs::<C, SC>(builder, config, opening_proof, challenger, rounds);
        builder.cycle_tracker("stage-d-verify-pcs");

        // // builder.cycle_tracker("stage-e-verify-constraints");

        // // for chip in machine.chips() {
        // //     if chip.name() == *sorted_chip {
        // //         let values = &opened_values.chips[i];
        // //         let trace_domain = &trace_domains[i];
        // //         let quotient_domain = &quotient_domains[i];
        // //         let qc_domains =
        // //             quotient_domain.split_domains_const(builder, chip.log_quotient_degree());
        // //         Self::verify_constraints(
        // //             builder,
        // //             chip,
        // //             values,
        // //             proof.public_values.clone(),
        // //             trace_domain.clone(),
        // //             qc_domains,
        // //             zeta,
        // //             alpha,
        // //             &permutation_challenges,
        // //         );
        // //     }
        // // }
        // // let num_shard_chips_enabled: Var<_> = builder.eval(C::N::zero());
        // // for (i, chip) in machine.chips().iter().enumerate() {
        // //     tracing::debug!("verifying constraints for chip: {}", chip.name());
        // //     let index = proof.sorted_idxs[i];
        // //     builder
        // //         .if_ne(index, C::N::from_canonical_usize(EMPTY))
        // //         .then(|builder| {
        // //             let values = builder.get(&opened_values.chips, index);
        // //             let trace_domain = builder.get(&trace_domains, index);
        // //             let quotient_domain: TwoAdicMultiplicativeCosetVariable<_> =
        // //                 builder.get(&quotient_domains, index);

        // //             // Check that the quotient data matches the chip's data.
        // //             let log_quotient_degree = chip.log_quotient_degree();

        // //             let quotient_size = 1 << log_quotient_degree;
        // //             let chip_quotient_data = builder.get(&proof.quotient_data, index);
        // //             builder.assert_usize_eq(
        // //                 chip_quotient_data.log_quotient_degree,
        // //                 log_quotient_degree,
        // //             );
        // //             builder.assert_usize_eq(chip_quotient_data.quotient_size, quotient_size);

        // //             // Get the domains from the chip itself.
        // //             let qc_domains =
        // //                 quotient_domain.split_domains_const(builder, log_quotient_degree);

        // //             // Verify the constraints.
        // //             stacker::maybe_grow(16 * 1024 * 1024, 16 * 1024 * 1024, || {
        // //                 Self::verify_constraints(
        // //                     builder,
        // //                     chip,
        // //                     &values,
        // //                     proof.public_values.clone(),
        // //                     trace_domain,
        // //                     qc_domains,
        // //                     zeta,
        // //                     alpha,
        // //                     &permutation_challenges,
        // //                 );
        //             });

        //             // Increment the number of shard chips that are enabled.
        //             builder.assign(
        //                 num_shard_chips_enabled,
        //                 num_shard_chips_enabled + C::N::one(),
        //             );
        //         });
        // }

        // Assert that the number of chips in `opened_values` matches the number of shard chips enabled.
        // builder.assert_var_eq(num_shard_chips_enabled, num_shard_chips);

        // // If we're checking the cumulative sum, assert that the sum of the cumulative sums is zero.
        // if check_cumulative_sum {
        //     let sum: Ext<_, _> = builder.eval(C::EF::zero().cons());
        //     builder
        //         .range(0, proof.opened_values.chips.len())
        //         .for_each(|i, builder| {
        //             let cumulative_sum = builder.get(&proof.opened_values.chips, i).cumulative_sum;
        //             builder.assign(sum, sum + cumulative_sum);
        //         });
        //     builder.assert_ext_eq(sum, C::EF::zero().cons());
        // }

        // builder.cycle_tracker("stage-e-verify-constraints");
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::VecDeque;

    use crate::challenger::CanObserveVariable;
    use crate::challenger::DuplexChallengerVariable;
    use p3_challenger::{CanObserve, FieldChallenger};
    use sp1_core::io::SP1Stdin;
    use sp1_core::runtime::Program;
    use sp1_core::stark::CpuProver;
    use sp1_core::utils::InnerChallenge;
    use sp1_core::utils::InnerVal;
    use sp1_core::utils::SP1CoreOpts;
    use sp1_core::{
        stark::{RiscvAir, StarkGenericConfig},
        utils::BabyBearPoseidon2,
    };
    use sp1_recursion_compiler::config::InnerConfig;
    use sp1_recursion_compiler::ir::{Builder, ExtConst};

    use sp1_recursion_core::runtime::DIGEST_SIZE;

    use super::*;
    use crate::challenger::tests::run_test_recursion;
    use crate::witness::*;

    type SC = BabyBearPoseidon2;
    type F = InnerVal;
    type EF = InnerChallenge;
    type C = InnerConfig;
    type A = RiscvAir<F>;

    #[test]
    fn test_permutation_challenges() {
        // Generate a dummy proof.
        sp1_core::utils::setup_logger();
        let elf = include_bytes!("../../../tests/fibonacci/elf/riscv32im-succinct-zkvm-elf");

        let machine = A::machine(SC::default());
        let (_, vk) = machine.setup(&Program::from(elf));
        let mut challenger_val = machine.config().challenger();
        let (proof, _, _) = sp1_core::utils::prove::<_, CpuProver<_, _>>(
            Program::from(elf),
            &SP1Stdin::new(),
            SC::default(),
            SP1CoreOpts::default(),
        )
        .unwrap();
        let proofs = proof.shard_proofs;
        println!("Proof generated successfully");

        challenger_val.observe(vk.commit);

        proofs.iter().for_each(|proof| {
            challenger_val.observe(proof.commitment.main_commit);
            challenger_val.observe_slice(&proof.public_values[0..machine.num_pv_elts()]);
        });

        let permutation_challenges = (0..2)
            .map(|_| challenger_val.sample_ext_element::<EF>())
            .collect::<Vec<_>>();

        // Observe all the commitments.
        let mut builder = Builder::<InnerConfig>::default();

        // Add a hash invocation, since the poseidon2 table expects that it's in the first row.
        // let hash_input = vec![builder.constant(F::one())];
        // builder.poseidon2_hash_v2(&hash_input);

        let mut challenger = DuplexChallengerVariable::new(&mut builder);

        let preprocessed_commit_val: [F; DIGEST_SIZE] = vk.commit.into();
        let preprocessed_commit: [Felt<F>; DIGEST_SIZE] = builder.constant(preprocessed_commit_val);
        challenger.observe_slice(&mut builder, preprocessed_commit);

        let mut witness_stream = VecDeque::<Witness<C>>::new();
        for proof in proofs {
            witness_stream.extend(proof.write());
            let proof = proof.read(&mut builder);
            let ShardCommitmentVariable { main_commit, .. } = proof.commitment;
            challenger.observe_slice(&mut builder, main_commit);
            let pv_slice = &proof.public_values[..machine.num_pv_elts()];
            challenger.observe_slice(&mut builder, pv_slice.iter().cloned());
        }

        // Sample the permutation challenges.
        let permutation_challenges_var = (0..2)
            .map(|_| challenger.sample_ext(&mut builder))
            .collect::<Vec<_>>();

        for i in 0..2 {
            builder.assert_ext_eq(
                permutation_challenges_var[i],
                permutation_challenges[i].cons(),
            );
        }

        run_test_recursion(builder.operations, witness_stream);
    }

    // fn test_public_values_program() -> RecursionProgram<InnerVal> {
    //     let mut builder = Builder::<InnerConfig>::default();

    //     // Add a hash invocation, since the poseidon2 table expects that it's in the first row.
    //     let hash_input = builder.constant(vec![vec![F::one()]]);
    //     builder.poseidon2_hash_x(&hash_input);

    //     let mut public_values_stream: Vec<Felt<_>> = (0..RECURSIVE_PROOF_NUM_PV_ELTS)
    //         .map(|_| builder.uninit())
    //         .collect();

    //     let public_values: &mut RecursionPublicValues<_> =
    //         public_values_stream.as_mut_slice().borrow_mut();

    //     public_values.sp1_vk_digest = [builder.constant(<C as Config>::F::zero()); DIGEST_SIZE];
    //     public_values.next_pc = builder.constant(<C as Config>::F::one());
    //     public_values.next_execution_shard = builder.constant(<C as Config>::F::two());
    //     public_values.end_reconstruct_deferred_digest =
    //         [builder.constant(<C as Config>::F::from_canonical_usize(3)); POSEIDON_NUM_WORDS];

    //     public_values.deferred_proofs_digest =
    //         [builder.constant(<C as Config>::F::from_canonical_usize(4)); POSEIDON_NUM_WORDS];

    //     public_values.cumulative_sum =
    //         [builder.constant(<C as Config>::F::from_canonical_usize(5)); 4];

    //     commit_public_values(&mut builder, public_values);
    //     builder.halt();

    //     builder.compile_program()
    // }

    // #[test]
    // fn test_public_values_failure() {
    //     let program = test_public_values_program();

    //     let config = SC::default();

    //     let mut runtime = Runtime::<InnerVal, Challenge, _>::new(&program, config.perm.clone());
    //     runtime.run().unwrap();

    //     let machine = RecursionAir::<_, 3>::machine(SC::default());
    //     let prover = CpuProver::new(machine);
    //     let (pk, vk) = prover.setup(&program);
    //     let record = runtime.record.clone();

    //     let mut challenger = prover.config().challenger();
    //     let mut proof = prover
    //         .prove(&pk, vec![record], &mut challenger, SP1CoreOpts::recursion())
    //         .unwrap();

    //     let mut challenger = prover.config().challenger();
    //     let verification_result = prover.machine().verify(&vk, &proof, &mut challenger);
    //     if verification_result.is_err() {
    //         panic!("Proof should verify successfully");
    //     }

    //     // Corrupt the public values.
    //     proof.shard_proofs[0].public_values[RECURSION_PUBLIC_VALUES_COL_MAP.digest[0]] =
    //         InnerVal::zero();
    //     let verification_result = prover.machine().verify(&vk, &proof, &mut challenger);
    //     if verification_result.is_ok() {
    //         panic!("Proof should not verify successfully");
    //     }
    // }

    // #[test]
    // #[ignore]
    // fn test_kitchen_sink() {
    //     setup_logger();

    //     let mut builder = AsmBuilder::<F, EF>::default();

    //     let a: Felt<_> = builder.eval(F::from_canonical_u32(23));
    //     let b: Felt<_> = builder.eval(F::from_canonical_u32(17));
    //     let a_plus_b = builder.eval(a + b);
    //     let mut rng = rand::thread_rng();
    //     let a_ext_val = rng.gen::<EF>();
    //     let b_ext_val = rng.gen::<EF>();
    //     let a_ext: Ext<_, _> = builder.eval(a_ext_val.cons());
    //     let b_ext: Ext<_, _> = builder.eval(b_ext_val.cons());
    //     let a_plus_b_ext = builder.eval(a_ext + b_ext);
    //     builder.print_f(a_plus_b);
    //     builder.print_e(a_plus_b_ext);
    //     builder.halt();

    //     run_test_recursion(builder.operations, None);
    // }
}
