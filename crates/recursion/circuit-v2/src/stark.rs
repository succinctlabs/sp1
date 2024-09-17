use hashbrown::HashMap;
use itertools::{izip, Itertools};
use num_traits::cast::ToPrimitive;
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_commit::{Mmcs, Pcs, PolynomialSpace, TwoAdicMultiplicativeCoset};
use p3_field::{Field, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;

use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, Ext},
    prelude::Felt,
};
use sp1_stark::{air::InteractionScope, ShardCommitment, ShardOpenedValues, Val};
use sp1_stark::{air::MachineAir, StarkGenericConfig, StarkMachine, StarkVerifyingKey};

use crate::{
    challenger::CanObserveVariable, hash::FieldHasherVariable, CircuitConfig,
    TwoAdicPcsMatsVariable, TwoAdicPcsProofVariable,
};

use crate::{
    challenger::FieldChallengerVariable, constraints::RecursiveVerifierConstraintFolder,
    domain::PolynomialSpaceVariable, fri::verify_two_adic_pcs, BabyBearFriConfigVariable,
    TwoAdicPcsRoundVariable, VerifyingKeyVariable,
};

/// Reference: [sp1_core::stark::ShardProof]
#[derive(Clone)]
pub struct ShardProofVariable<C: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<C>> {
    pub commitment: ShardCommitment<SC::DigestVariable>,
    pub opened_values: ShardOpenedValues<Ext<C::F, C::EF>>,
    pub opening_proof: TwoAdicPcsProofVariable<C, SC>,
    pub chip_ordering: HashMap<String, usize>,
    pub chip_scopes: Vec<InteractionScope>,
    pub public_values: Vec<Felt<C::F>>,
}

#[derive(Clone)]
pub struct MerkleProofVariable<C: CircuitConfig, HV: FieldHasherVariable<C>> {
    pub index: Vec<C::Bit>,
    pub path: Vec<HV::DigestVariable>,
}

pub const EMPTY: usize = 0x_1111_1111;

#[derive(Debug, Clone, Copy)]
pub struct StarkVerifier<C: Config, SC: StarkGenericConfig, A> {
    _phantom: std::marker::PhantomData<(C, SC, A)>,
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

impl<C, SC, A> StarkVerifier<C, SC, A>
where
    C::F: TwoAdicField,
    C: CircuitConfig<F = SC::Val>,
    SC: BabyBearFriConfigVariable<C>,
    <SC::ValMmcs as Mmcs<BabyBear>>::ProverData<RowMajorMatrix<BabyBear>>: Clone,
    A: MachineAir<Val<SC>>,
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

    pub fn verify_shard(
        builder: &mut Builder<C>,
        vk: &VerifyingKeyVariable<C, SC>,
        machine: &StarkMachine<SC, A>,
        challenger: &mut SC::FriChallengerVariable,
        proof: &ShardProofVariable<C, SC>,
        global_permutation_challenges: &[Ext<C::F, C::EF>],
    ) where
        A: for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
    {
        let chips = machine.shard_chips_ordered(&proof.chip_ordering).collect::<Vec<_>>();

        let has_global_main_commit = proof.contains_global_main_commitment();

        let ShardProofVariable {
            commitment,
            opened_values,
            opening_proof,
            chip_ordering,
            chip_scopes,
            public_values,
        } = proof;

        // Assert that the byte multiplicities don't overflow.
        let mut max_byte_lookup_mult = 0u64;
        chips.iter().zip(opened_values.chips.iter()).for_each(|(chip, val)| {
            max_byte_lookup_mult = max_byte_lookup_mult
                .checked_add(
                    (chip.num_sent_byte_lookups() as u64)
                        .checked_mul(1u64.checked_shl(val.log_degree as u32).unwrap())
                        .unwrap(),
                )
                .unwrap();
        });

        assert!(
            max_byte_lookup_mult <= SC::Val::order().to_u64().unwrap(),
            "Byte multiplicities overflow"
        );

        let log_degrees = opened_values.chips.iter().map(|val| val.log_degree).collect::<Vec<_>>();

        let log_quotient_degrees =
            chips.iter().map(|chip| chip.log_quotient_degree()).collect::<Vec<_>>();

        let trace_domains = log_degrees
            .iter()
            .map(|log_degree| Self::natural_domain_for_degree(machine.config(), 1 << log_degree))
            .collect::<Vec<_>>();

        let ShardCommitment {
            global_main_commit,
            local_main_commit,
            permutation_commit,
            quotient_commit,
        } = *commitment;

        challenger.observe(builder, local_main_commit);

        let local_permutation_challenges =
            (0..2).map(|_| challenger.sample_ext(builder)).collect::<Vec<_>>();

        challenger.observe(builder, permutation_commit);

        let alpha = challenger.sample_ext(builder);

        challenger.observe(builder, quotient_commit);

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
                values: vec![values.permutation.local.clone(), values.permutation.next.clone()],
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
                values.quotient.iter().zip_eq(qc_domains).map(move |(values, q_domain)| {
                    TwoAdicPcsMatsVariable::<C> {
                        domain: *q_domain,
                        points: vec![zeta],
                        values: vec![values.clone()],
                    }
                })
            })
            .collect::<Vec<_>>();

        // Split the main_domains_points_and_opens to the global and local chips.
        let mut global_trace_points_and_openings = Vec::new();
        let mut local_trace_points_and_openings = Vec::new();
        for (i, points_and_openings) in
            main_domains_points_and_opens.clone().into_iter().enumerate()
        {
            let scope = chip_scopes[i];
            if scope == InteractionScope::Global {
                global_trace_points_and_openings.push(points_and_openings);
            } else {
                local_trace_points_and_openings.push(points_and_openings);
            }
        }

        // Create the pcs rounds.
        let prep_commit = vk.commitment;
        let prep_round = TwoAdicPcsRoundVariable {
            batch_commit: prep_commit,
            domains_points_and_opens: preprocessed_domains_points_and_opens,
        };
        let global_main_round = TwoAdicPcsRoundVariable {
            batch_commit: global_main_commit,
            domains_points_and_opens: global_trace_points_and_openings,
        };
        let local_main_round = TwoAdicPcsRoundVariable {
            batch_commit: local_main_commit,
            domains_points_and_opens: local_trace_points_and_openings,
        };
        let perm_round = TwoAdicPcsRoundVariable {
            batch_commit: permutation_commit,
            domains_points_and_opens: perm_domains_points_and_opens,
        };
        let quotient_round = TwoAdicPcsRoundVariable {
            batch_commit: quotient_commit,
            domains_points_and_opens: quotient_domains_points_and_opens,
        };

        let rounds = if has_global_main_commit {
            vec![prep_round, global_main_round, local_main_round, perm_round, quotient_round]
        } else {
            vec![prep_round, local_main_round, perm_round, quotient_round]
        };

        // Verify the pcs proof
        builder.cycle_tracker_v2_enter("stage-d-verify-pcs".to_string());
        let config = machine.config().fri_config();
        verify_two_adic_pcs::<C, SC>(builder, config, opening_proof, challenger, rounds);
        builder.cycle_tracker_v2_exit();

        // Verify the constrtaint evaluations.
        builder.cycle_tracker_v2_enter("stage-e-verify-constraints".to_string());
        let permutation_challenges = global_permutation_challenges
            .iter()
            .chain(local_permutation_challenges.iter())
            .copied()
            .collect::<Vec<_>>();

        for (chip, trace_domain, qc_domains, values) in
            izip!(chips.iter(), trace_domains, quotient_chunk_domains, opened_values.chips.iter(),)
        {
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

impl<C: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<C>> ShardProofVariable<C, SC> {
    pub fn contains_cpu(&self) -> bool {
        self.chip_ordering.contains_key("CPU")
    }

    pub fn log_degree_cpu(&self) -> usize {
        let idx = self.chip_ordering.get("CPU").expect("CPU chip not found");
        self.opened_values.chips[*idx].log_degree
    }

    pub fn contains_memory_init(&self) -> bool {
        self.chip_ordering.contains_key("MemoryGlobalInit")
    }

    pub fn contains_memory_finalize(&self) -> bool {
        self.chip_ordering.contains_key("MemoryGlobalFinalize")
    }

    pub fn contains_global_main_commitment(&self) -> bool {
        self.chip_scopes.contains(&InteractionScope::Global)
    }
}

#[allow(unused_imports)]
#[cfg(any(test, feature = "export-tests"))]
pub mod tests {
    use std::collections::VecDeque;

    use crate::{
        challenger::{CanCopyChallenger, CanObserveVariable, DuplexChallengerVariable},
        utils::tests::run_test_recursion_with_prover,
        BabyBearFriConfig,
    };

    use sp1_core_executor::{programs::tests::FIBONACCI_ELF, Program};
    use sp1_core_machine::{
        io::SP1Stdin,
        riscv::RiscvAir,
        utils::{prove, setup_logger},
    };
    use sp1_recursion_compiler::{
        config::{InnerConfig, OuterConfig},
        ir::{Builder, DslIr, TracedVec},
    };

    use sp1_recursion_core_v2::{
        air::Block, machine::RecursionAir, stark::config::BabyBearPoseidon2Outer,
    };
    use sp1_stark::{
        baby_bear_poseidon2::BabyBearPoseidon2, CpuProver, InnerVal, MachineProver, SP1CoreOpts,
        ShardProof,
    };

    use super::*;
    use crate::witness::*;

    type F = InnerVal;
    type A = RiscvAir<F>;

    pub fn build_verify_shard_with_provers<
        C: CircuitConfig<F = InnerVal, Bit = Felt<InnerVal>>,
        SC: BabyBearFriConfigVariable<C> + Default + Sync + Send,
        CoreP: MachineProver<SC, A>,
        RecP: MachineProver<SC, RecursionAir<F, 3, 0>>,
    >(
        config: SC,
        elf: &[u8],
        opts: SP1CoreOpts,
        num_shards_in_batch: Option<usize>,
    ) -> (TracedVec<DslIr<C>>, Vec<Block<BabyBear>>)
    where
        SC::Challenger: Send,
        <<SC as BabyBearFriConfig>::ValMmcs as Mmcs<BabyBear>>::ProverData<
            RowMajorMatrix<BabyBear>,
        >: Send + Sync,
        <<SC as BabyBearFriConfig>::ValMmcs as Mmcs<BabyBear>>::Commitment: Send + Sync,
        <<SC as BabyBearFriConfig>::ValMmcs as Mmcs<BabyBear>>::Proof: Send,
        StarkVerifyingKey<SC>: Witnessable<C, WitnessVariable = VerifyingKeyVariable<C, SC>>,
        ShardProof<SC>: Witnessable<C, WitnessVariable = ShardProofVariable<C, SC>>,
    {
        // Generate a dummy proof.
        setup_logger();

        let machine = RiscvAir::<C::F>::machine(SC::default());
        let (_, vk) = machine.setup(&Program::from(elf).unwrap());
        let (proof, _, _) =
            prove::<_, CoreP>(Program::from(elf).unwrap(), &SP1Stdin::new(), SC::default(), opts)
                .unwrap();
        let mut challenger = machine.config().challenger();
        machine.verify(&vk, &proof, &mut challenger).unwrap();
        println!("Proof generated successfully");

        // Observe all the commitments.
        let mut builder = Builder::<C>::default();

        let mut witness_stream = Vec::<WitnessBlock<C>>::new();

        // Add a hash invocation, since the poseidon2 table expects that it's in the first row.
        let mut challenger = config.challenger_variable(&mut builder);
        // let vk = VerifyingKeyVariable::from_constant_key_babybear(&mut builder, &vk);
        vk.write(&mut witness_stream);
        let vk: VerifyingKeyVariable<_, _> = vk.read(&mut builder);
        vk.observe_into(&mut builder, &mut challenger);

        let proofs = proof
            .shard_proofs
            .into_iter()
            .map(|proof| {
                proof.write(&mut witness_stream);
                proof.read(&mut builder)
            })
            .collect::<Vec<_>>();
        // Observe all the commitments, and put the proofs into the witness stream.
        for proof in proofs.iter() {
            let ShardCommitment { global_main_commit, .. } = proof.commitment;
            challenger.observe(&mut builder, global_main_commit);
            let pv_slice = &proof.public_values[..machine.num_pv_elts()];
            challenger.observe_slice(&mut builder, pv_slice.iter().cloned());
        }

        let global_permutation_challenges =
            (0..2).map(|_| challenger.sample_ext(&mut builder)).collect::<Vec<_>>();

        // Verify the first proof.
        let num_shards = num_shards_in_batch.unwrap_or(proofs.len());
        for proof in proofs.into_iter().take(num_shards) {
            let mut challenger = challenger.copy(&mut builder);
            StarkVerifier::verify_shard(
                &mut builder,
                &vk,
                &machine,
                &mut challenger,
                &proof,
                &global_permutation_challenges,
            );
        }
        (builder.into_operations(), witness_stream)
    }

    #[test]
    fn test_verify_shard_inner() {
        let (operations, stream) =
            build_verify_shard_with_provers::<
                InnerConfig,
                BabyBearPoseidon2,
                CpuProver<_, _>,
                CpuProver<_, _>,
            >(BabyBearPoseidon2::new(), FIBONACCI_ELF, SP1CoreOpts::default(), Some(2));
        run_test_recursion_with_prover::<CpuProver<_, _>>(operations, stream);
    }
}
