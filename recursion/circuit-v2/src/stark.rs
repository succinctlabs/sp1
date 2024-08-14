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
use sp1_recursion_compiler::circuit::CircuitV2Builder;
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

        // Verify the pcs proof
        builder.cycle_tracker_v2_enter("stage-d-verify-pcs".to_string());
        let config = machine.config().fri_config();
        verify_two_adic_pcs::<C, SC>(builder, config, opening_proof, challenger, rounds);
        builder.cycle_tracker_v2_exit();

        // Verify the constrtaint evaluations.
        builder.cycle_tracker_v2_enter("stage-e-verify-constraints".to_string());
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
        builder.cycle_tracker_v2_exit();
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

    use sp1_recursion_core_v2::runtime::DIGEST_SIZE;

    use super::*;
    use crate::utils::tests::run_test_recursion;
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
        let elf = FIBONACCI_ELF;

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
    fn test_verify_shard() {
        // Generate a dummy proof.
        sp1_core::utils::setup_logger();
        let elf = FIBONACCI_ELF;

        let machine = A::machine(SC::default());
        let (_, vk) = machine.setup(&Program::from(elf));
        let (proof, _, _) = sp1_core::utils::prove::<_, CpuProver<_, _>>(
            Program::from(elf),
            &SP1Stdin::new(),
            SC::default(),
            SP1CoreOpts::default(),
        )
        .unwrap();
        let mut challenger = machine.config().challenger();
        machine.verify(&vk, &proof, &mut challenger).unwrap();
        println!("Proof generated successfully");

        // Observe all the commitments.
        let mut builder = Builder::<InnerConfig>::default();

        // Add a hash invocation, since the poseidon2 table expects that it's in the first row.
        let mut challenger = DuplexChallengerVariable::new(&mut builder);
        let vk = VerifyingKeyVariable::from_constant_key_babybear(&mut builder, &vk);
        vk.observe_into(&mut builder, &mut challenger);

        let mut witness_stream = VecDeque::<Witness<C>>::new();
        let proofs = proof
            .shard_proofs
            .into_iter()
            .map(|proof| {
                witness_stream.extend(Witnessable::<C>::write(&proof));
                proof.read(&mut builder)
            })
            .collect::<Vec<_>>();
        // Observe all the commitments, and put the proofs into the witness stream.
        for proof in proofs.iter() {
            let ShardCommitmentVariable { main_commit, .. } = proof.commitment;
            challenger.observe(&mut builder, main_commit);
            let pv_slice = &proof.public_values[..machine.num_pv_elts()];
            challenger.observe_slice(&mut builder, pv_slice.iter().cloned());
        }
        // Verify the first proof.
        for proof in proofs.into_iter() {
            let mut challenger = challenger.copy(&mut builder);
            StarkVerifier::<C, SC>::verify_shard::<A>(
                &mut builder,
                &vk,
                &machine,
                &mut challenger,
                &proof,
            );
        }

        run_test_recursion(builder.operations, witness_stream);
    }
}
