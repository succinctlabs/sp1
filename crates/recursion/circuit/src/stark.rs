use hashbrown::HashMap;
use itertools::{izip, Itertools};

use num_traits::cast::ToPrimitive;

use crate::{
    challenger::CanObserveVariable,
    fri::{dummy_hash, dummy_pcs_proof, PolynomialBatchShape, PolynomialShape},
    hash::FieldHasherVariable,
    BabyBearFriConfig, CircuitConfig, TwoAdicPcsMatsVariable, TwoAdicPcsProofVariable,
};
use p3_air::{Air, BaseAir};
use p3_baby_bear::BabyBear;
use p3_commit::{Mmcs, Pcs, PolynomialSpace, TwoAdicMultiplicativeCoset};
use p3_field::{AbstractField, ExtensionField, Field, TwoAdicField};
use p3_matrix::{dense::RowMajorMatrix, Dimensions};
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, Ext, ExtConst},
    prelude::Felt,
};
use sp1_stark::{
    air::{InteractionScope, MachineAir},
    baby_bear_poseidon2::BabyBearPoseidon2,
    shape::OrderedShape,
    AirOpenedValues, Challenger, Chip, ChipOpenedValues, InnerChallenge, InteractionKind,
    ShardCommitment, ShardOpenedValues, ShardProof, StarkGenericConfig, StarkMachine,
    StarkVerifyingKey, Val, PROOF_MAX_NUM_PVS,
};

use crate::{
    challenger::FieldChallengerVariable, constraints::RecursiveVerifierConstraintFolder,
    domain::PolynomialSpaceVariable, fri::verify_two_adic_pcs, BabyBearFriConfigVariable,
    TwoAdicPcsRoundVariable, VerifyingKeyVariable,
};
use sp1_stark::septic_digest::SepticDigest;

/// Reference: [sp1_core::stark::ShardProof]
#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct ShardProofVariable<C: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<C>> {
    pub commitment: ShardCommitment<SC::DigestVariable>,
    pub opened_values: ShardOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
    pub opening_proof: TwoAdicPcsProofVariable<C, SC>,
    pub chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<Felt<C::F>>,
}

/// Get a dummy duplex challenger for use in dummy proofs.
pub fn dummy_challenger(config: &BabyBearPoseidon2) -> Challenger<BabyBearPoseidon2> {
    let mut challenger = config.challenger();
    challenger.input_buffer = vec![];
    challenger.output_buffer = vec![BabyBear::zero(); challenger.sponge_state.len()];
    challenger
}

/// Make a dummy shard proof for a given proof shape.
pub fn dummy_vk_and_shard_proof<A: MachineAir<BabyBear>>(
    machine: &StarkMachine<BabyBearPoseidon2, A>,
    shape: &OrderedShape,
) -> (StarkVerifyingKey<BabyBearPoseidon2>, ShardProof<BabyBearPoseidon2>) {
    // Make a dummy commitment.
    let commitment = ShardCommitment {
        main_commit: dummy_hash(),
        permutation_commit: dummy_hash(),
        quotient_commit: dummy_hash(),
    };

    // Get dummy opened values by reading the chip ordering from the shape.
    let chip_ordering = shape
        .inner
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (name.clone(), i))
        .collect::<HashMap<_, _>>();
    let shard_chips = machine.shard_chips_ordered(&chip_ordering).collect::<Vec<_>>();
    let opened_values = ShardOpenedValues {
        chips: shard_chips
            .iter()
            .zip_eq(shape.inner.iter())
            .map(|(chip, (_, log_degree))| {
                dummy_opened_values::<_, InnerChallenge, _>(chip, *log_degree)
            })
            .collect(),
    };

    let mut preprocessed_names_and_dimensions = vec![];
    let mut preprocessed_batch_shape = vec![];
    let mut main_batch_shape = vec![];
    let mut permutation_batch_shape = vec![];
    let mut quotient_batch_shape = vec![];

    for (chip, chip_opening) in shard_chips.iter().zip_eq(opened_values.chips.iter()) {
        if !chip_opening.preprocessed.local.is_empty() {
            let prep_shape = PolynomialShape {
                width: chip_opening.preprocessed.local.len(),
                log_degree: chip_opening.log_degree,
            };
            preprocessed_names_and_dimensions.push((
                chip.name(),
                prep_shape.width,
                prep_shape.log_degree,
            ));
            preprocessed_batch_shape.push(prep_shape);
        }
        let main_shape = PolynomialShape {
            width: chip_opening.main.local.len(),
            log_degree: chip_opening.log_degree,
        };
        main_batch_shape.push(main_shape);
        let permutation_shape = PolynomialShape {
            width: chip_opening.permutation.local.len(),
            log_degree: chip_opening.log_degree,
        };
        permutation_batch_shape.push(permutation_shape);
        for quot_chunk in chip_opening.quotient.iter() {
            assert_eq!(quot_chunk.len(), 4);
            quotient_batch_shape.push(PolynomialShape {
                width: quot_chunk.len(),
                log_degree: chip_opening.log_degree,
            });
        }
    }

    let batch_shapes = vec![
        PolynomialBatchShape { shapes: preprocessed_batch_shape },
        PolynomialBatchShape { shapes: main_batch_shape },
        PolynomialBatchShape { shapes: permutation_batch_shape },
        PolynomialBatchShape { shapes: quotient_batch_shape },
    ];

    let fri_queries = machine.config().fri_config().num_queries;
    let log_blowup = machine.config().fri_config().log_blowup;
    let opening_proof = dummy_pcs_proof(fri_queries, &batch_shapes, log_blowup);

    let public_values = (0..PROOF_MAX_NUM_PVS).map(|_| BabyBear::zero()).collect::<Vec<_>>();

    // Get the preprocessed chip information.
    let pcs = machine.config().pcs();
    let preprocessed_chip_information: Vec<_> = preprocessed_names_and_dimensions
        .iter()
        .map(|(name, width, log_height)| {
            let domain = <<BabyBearPoseidon2 as StarkGenericConfig>::Pcs as Pcs<
                <BabyBearPoseidon2 as StarkGenericConfig>::Challenge,
                <BabyBearPoseidon2 as StarkGenericConfig>::Challenger,
            >>::natural_domain_for_degree(pcs, 1 << log_height);
            (name.to_owned(), domain, Dimensions { width: *width, height: 1 << log_height })
        })
        .collect();

    // Get the chip ordering.
    let preprocessed_chip_ordering = preprocessed_names_and_dimensions
        .iter()
        .enumerate()
        .map(|(i, (name, _, _))| (name.to_owned(), i))
        .collect::<HashMap<_, _>>();

    let vk = StarkVerifyingKey {
        commit: dummy_hash(),
        pc_start: BabyBear::zero(),
        initial_global_cumulative_sum: SepticDigest::<BabyBear>::zero(),
        chip_information: preprocessed_chip_information,
        chip_ordering: preprocessed_chip_ordering,
    };

    let shard_proof =
        ShardProof { commitment, opened_values, opening_proof, chip_ordering, public_values };

    (vk, shard_proof)
}

fn dummy_opened_values<F: Field, EF: ExtensionField<F>, A: MachineAir<F>>(
    chip: &Chip<F, A>,
    log_degree: usize,
) -> ChipOpenedValues<F, EF> {
    let preprocessed_width = chip.preprocessed_width();
    let preprocessed = AirOpenedValues {
        local: vec![EF::zero(); preprocessed_width],
        next: vec![EF::zero(); preprocessed_width],
    };
    let main_width = chip.width();
    let main =
        AirOpenedValues { local: vec![EF::zero(); main_width], next: vec![EF::zero(); main_width] };

    let permutation_width = chip.permutation_width();
    let permutation = AirOpenedValues {
        local: vec![EF::zero(); permutation_width * EF::D],
        next: vec![EF::zero(); permutation_width * EF::D],
    };
    let quotient_width = chip.quotient_width();
    let quotient = (0..quotient_width).map(|_| vec![EF::zero(); EF::D]).collect::<Vec<_>>();

    ChipOpenedValues {
        preprocessed,
        main,
        permutation,
        quotient,
        global_cumulative_sum: SepticDigest::<F>::zero(),
        local_cumulative_sum: EF::zero(),
        log_degree,
    }
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
    ) where
        A: for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
    {
        let chips = machine.shard_chips_ordered(&proof.chip_ordering).collect::<Vec<_>>();

        let ShardProofVariable {
            commitment,
            opened_values,
            opening_proof,
            chip_ordering,
            public_values,
        } = proof;

        tracing::debug_span!("assert lookup multiplicities").in_scope(|| {
            // Assert that the lookup multiplicities don't overflow.
            for kind in InteractionKind::all_kinds() {
                let mut max_lookup_mult = 0u64;
                chips.iter().zip(opened_values.chips.iter()).for_each(|(chip, val)| {
                    max_lookup_mult = max_lookup_mult
                        .checked_add(
                            (chip.num_sends_by_kind(kind) as u64 +
                                chip.num_receives_by_kind(kind) as u64)
                                .checked_mul(1u64.checked_shl(val.log_degree as u32).unwrap())
                                .unwrap(),
                        )
                        .unwrap();
                });
                assert!(
                    max_lookup_mult < SC::Val::order().to_u64().unwrap(),
                    "Lookup multiplicities overflow"
                );
            }
        });

        let log_degrees = opened_values.chips.iter().map(|val| val.log_degree).collect::<Vec<_>>();

        let log_quotient_degrees =
            chips.iter().map(|chip| chip.log_quotient_degree()).collect::<Vec<_>>();

        let trace_domains = log_degrees
            .iter()
            .map(|log_degree| Self::natural_domain_for_degree(machine.config(), 1 << log_degree))
            .collect::<Vec<_>>();

        let ShardCommitment { main_commit, permutation_commit, quotient_commit } = *commitment;

        challenger.observe(builder, main_commit);

        let local_permutation_challenges =
            (0..2).map(|_| challenger.sample_ext(builder)).collect::<Vec<_>>();

        challenger.observe(builder, permutation_commit);

        // Observe all cumulative sums, and assert conditions on them.
        for (opening, chip) in opened_values.chips.iter().zip_eq(chips.iter()) {
            let local_sum = C::ext2felt(builder, opening.local_cumulative_sum);
            let global_sum = opening.global_cumulative_sum;

            challenger.observe_slice(builder, local_sum);
            challenger.observe_slice(builder, global_sum.0.x.0);
            challenger.observe_slice(builder, global_sum.0.y.0);

            // If the chip is local, then `global_cumulative_sum` must be zero.
            if chip.commit_scope() == InteractionScope::Local {
                let is_real: Felt<C::F> = builder.constant(C::F::one());
                builder.assert_digest_zero_v2(is_real, global_sum);
            }

            // If the chip has no local interactions, then `local_cumulative_sum` must be zero.
            let has_local_interactions = chip
                .sends()
                .iter()
                .chain(chip.receives())
                .any(|i| i.scope == InteractionScope::Local);
            if !has_local_interactions {
                builder.assert_ext_eq(opening.local_cumulative_sum, C::EF::zero().cons());
            }
        }

        let alpha = challenger.sample_ext(builder);

        challenger.observe(builder, quotient_commit);

        let zeta = challenger.sample_ext(builder);

        let preprocessed_domains_points_and_opens = vk
            .chip_information
            .iter()
            .map(|(name, domain, _)| {
                let i = chip_ordering[name];
                assert_eq!(name, &chips[i].name());
                let values = opened_values.chips[i].preprocessed.clone();
                if !chips[i].local_only() {
                    TwoAdicPcsMatsVariable::<C> {
                        domain: *domain,
                        points: vec![zeta, domain.next_point_variable(builder, zeta)],
                        values: vec![values.local, values.next],
                    }
                } else {
                    TwoAdicPcsMatsVariable::<C> {
                        domain: *domain,
                        points: vec![zeta],
                        values: vec![values.local],
                    }
                }
            })
            .collect::<Vec<_>>();

        let main_domains_points_and_opens = trace_domains
            .iter()
            .zip_eq(opened_values.chips.iter())
            .zip_eq(chips.iter())
            .map(|((domain, values), chip)| {
                if !chip.local_only() {
                    TwoAdicPcsMatsVariable::<C> {
                        domain: *domain,
                        points: vec![zeta, domain.next_point_variable(builder, zeta)],
                        values: vec![values.main.local.clone(), values.main.next.clone()],
                    }
                } else {
                    TwoAdicPcsMatsVariable::<C> {
                        domain: *domain,
                        points: vec![zeta],
                        values: vec![values.main.local.clone()],
                    }
                }
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

        // Create the pcs rounds.
        let prep_commit = vk.commitment;
        let prep_round = TwoAdicPcsRoundVariable {
            batch_commit: prep_commit,
            domains_points_and_opens: preprocessed_domains_points_and_opens,
        };
        let main_round = TwoAdicPcsRoundVariable {
            batch_commit: main_commit,
            domains_points_and_opens: main_domains_points_and_opens,
        };
        let perm_round = TwoAdicPcsRoundVariable {
            batch_commit: permutation_commit,
            domains_points_and_opens: perm_domains_points_and_opens,
        };
        let quotient_round = TwoAdicPcsRoundVariable {
            batch_commit: quotient_commit,
            domains_points_and_opens: quotient_domains_points_and_opens,
        };

        let rounds = vec![prep_round, main_round, perm_round, quotient_round];

        // Verify the pcs proof
        builder.cycle_tracker_v2_enter("stage-d-verify-pcs");
        let config = machine.config().fri_config();
        tracing::debug_span!("2adic pcs").in_scope(|| {
            verify_two_adic_pcs::<C, SC>(builder, config, opening_proof, challenger, rounds);
        });
        builder.cycle_tracker_v2_exit();

        // Verify the constrtaint evaluations.
        builder.cycle_tracker_v2_enter("stage-e-verify-constraints");
        let permutation_challenges = local_permutation_challenges;

        tracing::debug_span!("verify constraints").in_scope(|| {
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
        });

        // Verify that the chips' local_cumulative_sum sum to 0.
        let local_cumulative_sum: Ext<C::F, C::EF> = opened_values
            .chips
            .iter()
            .map(|val| val.local_cumulative_sum)
            .fold(builder.constant(C::EF::zero()), |acc, x| builder.eval(acc + x));
        let zero_ext: Ext<_, _> = builder.constant(C::EF::zero());
        builder.assert_ext_eq(local_cumulative_sum, zero_ext);

        builder.cycle_tracker_v2_exit();
    }
}

impl<C: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<C>> ShardProofVariable<C, SC> {
    pub fn contains_cpu(&self) -> bool {
        self.chip_ordering.contains_key("Cpu")
    }

    pub fn log_degree_cpu(&self) -> usize {
        let idx = self.chip_ordering.get("Cpu").expect("Cpu chip not found");
        self.opened_values.chips[*idx].log_degree
    }

    pub fn contains_memory_init(&self) -> bool {
        self.chip_ordering.contains_key("MemoryGlobalInit")
    }

    pub fn contains_memory_finalize(&self) -> bool {
        self.chip_ordering.contains_key("MemoryGlobalFinalize")
    }
}

#[allow(unused_imports)]
#[cfg(test)]
pub mod tests {
    use std::{collections::VecDeque, fmt::Debug};

    use crate::{
        challenger::{CanCopyChallenger, CanObserveVariable, DuplexChallengerVariable},
        utils::tests::run_test_recursion_with_prover,
        BabyBearFriConfig,
    };

    use sp1_core_executor::Program;
    use sp1_core_machine::{
        io::SP1Stdin,
        riscv::RiscvAir,
        utils::{prove_core, prove_core_stream, setup_logger},
    };
    use sp1_recursion_compiler::{
        config::{InnerConfig, OuterConfig},
        ir::{Builder, DslIr, DslIrBlock},
    };

    use sp1_core_executor::SP1Context;
    use sp1_recursion_core::{air::Block, machine::RecursionAir, stark::BabyBearPoseidon2Outer};
    use sp1_stark::{
        baby_bear_poseidon2::BabyBearPoseidon2, CpuProver, InnerVal, MachineProver, SP1CoreOpts,
        ShardProof,
    };
    use test_artifacts::FIBONACCI_ELF;

    use super::*;
    use crate::witness::*;

    type F = InnerVal;
    type A = RiscvAir<F>;
    type SC = BabyBearPoseidon2;

    pub fn build_verify_shard_with_provers<
        C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<InnerVal>> + Debug,
        CoreP: MachineProver<SC, A>,
        RecP: MachineProver<SC, RecursionAir<F, 3>>,
    >(
        config: SC,
        elf: &[u8],
        opts: SP1CoreOpts,
        num_shards_in_batch: Option<usize>,
    ) -> (DslIrBlock<C>, Vec<Block<BabyBear>>) {
        setup_logger();

        let program = Program::from(elf).unwrap();
        let machine = RiscvAir::<C::F>::machine(SC::default());
        let prover = CoreP::new(machine);
        let (pk, vk) = prover.setup(&program);

        let (proof, _, _) = prove_core::<_, CoreP>(
            &prover,
            &pk,
            &vk,
            program,
            &SP1Stdin::new(),
            opts,
            SP1Context::default(),
            None,
            None,
        )
        .unwrap();

        let machine = RiscvAir::<C::F>::machine(SC::default());
        let mut challenger = machine.config().challenger();
        machine.verify(&vk, &proof, &mut challenger).unwrap();

        let mut builder = Builder::<C>::default();

        let mut witness_stream = Vec::<WitnessBlock<C>>::new();

        // Add a hash invocation, since the poseidon2 table expects that it's in the first row.
        let mut challenger = config.challenger_variable(&mut builder);
        // let vk = VerifyingKeyVariable::from_constant_key_babybear(&mut builder, &vk);
        Witnessable::<C>::write(&vk, &mut witness_stream);
        let vk: VerifyingKeyVariable<_, _> = vk.read(&mut builder);
        vk.observe_into(&mut builder, &mut challenger);

        let proofs = proof
            .shard_proofs
            .into_iter()
            .map(|proof| {
                let shape = proof.shape();
                let (_, dummy_proof) = dummy_vk_and_shard_proof(&machine, &shape);
                Witnessable::<C>::write(&proof, &mut witness_stream);
                dummy_proof.read(&mut builder)
            })
            .collect::<Vec<_>>();

        // Verify the first proof.
        let num_shards = num_shards_in_batch.unwrap_or(proofs.len());
        for proof in proofs.into_iter().take(num_shards) {
            let mut challenger = challenger.copy(&mut builder);
            let pv_slice = &proof.public_values[..machine.num_pv_elts()];
            challenger.observe_slice(&mut builder, pv_slice.iter().cloned());
            StarkVerifier::verify_shard(&mut builder, &vk, &machine, &mut challenger, &proof);
        }
        (builder.into_root_block(), witness_stream)
    }

    #[test]
    fn test_verify_shard_inner() {
        let (operations, stream) =
            build_verify_shard_with_provers::<InnerConfig, CpuProver<_, _>, CpuProver<_, _>>(
                BabyBearPoseidon2::new(),
                FIBONACCI_ELF,
                SP1CoreOpts::default(),
                Some(2),
            );
        run_test_recursion_with_prover::<CpuProver<_, _>>(operations, stream);
    }
}
