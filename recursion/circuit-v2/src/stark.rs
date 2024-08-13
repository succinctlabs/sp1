use hashbrown::HashMap;
use itertools::izip;
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
use sp1_core::stark::ShardOpenedValues;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::stark::StarkMachine;
use sp1_core::stark::Val;

use sp1_core::stark::StarkVerifyingKey;
use sp1_recursion_compiler::ir::{Builder, Config, Ext};
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
    pub opened_values: ShardOpenedValues<Ext<C::F, C::EF>>,
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
            public_values,
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

        let permutation_challenges = (0..2)
            .map(|_| challenger.sample_ext(builder))
            .collect::<Vec<_>>();

        challenger.observe_slice(builder, *permutation_commit);

        let alpha = challenger.sample_ext(builder);

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

        // Verify the constrtaint evaluations.
        builder.cycle_tracker("stage-e-verify-constraints");
        for (chip, trace_domain, qc_domains, values) in izip!(
            chips.iter(),
            trace_domains,
            quotient_chunk_domains,
            opened_values.chips.iter(),
        ) {
            // Verify the shape of the opening arguments matches the expected values.
            Self::verify_opening_shape(chip, values).unwrap();
            // Verify the constraint evaluation.
            Self::verify_constraints(
                builder,
                chip,
                values,
                trace_domain,
                qc_domains,
                zeta,
                alpha,
                &permutation_challenges,
                public_values,
            );
        }
        builder.cycle_tracker("stage-e-verify-constraints");

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
    use sp1_core::utils::tests::FIBONACCI_ELF;
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
        let mut challenger = DuplexChallengerVariable::new(&mut builder);

        let preprocessed_commit_val: [F; DIGEST_SIZE] = vk.commit.into();
        let preprocessed_commit = builder.constant(preprocessed_commit_val);
        challenger.observe_commitment(&mut builder, preprocessed_commit);

        let mut witness_stream = VecDeque::<Witness<C>>::new();
        for proof in proofs {
            witness_stream.extend(Witnessable::<C>::write(&proof));
            let proof = proof.read(&mut builder);
            let ShardCommitmentVariable { main_commit, .. } = proof.commitment;
            challenger.observe_commitment(&mut builder, main_commit);
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

    #[test]
    fn test_verify_shard() {}
}
