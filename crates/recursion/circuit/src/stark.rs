use std::{borrow::Borrow, fmt::Debug, marker::PhantomData};

use crate::{
    fri::verify_two_adic_pcs,
    poseidon2::Poseidon2CircuitBuilder,
    types::OuterDigestVariable,
    utils::{babybear_bytes_to_bn254, babybears_to_bn254, words_to_bytes},
    witness::Witnessable,
};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractField, TwoAdicField};
use p3_util::log2_strict_usize;
use sp1_core_machine::utils::{Span, SpanBuilder, SpanBuilderError};
use sp1_recursion_compiler::{
    config::OuterConfig,
    constraints::{Constraint, ConstraintCompiler},
    ir::{Builder, Config, DslIr, Ext, Felt, Usize, Var, Witness},
    prelude::SymbolicVar,
};
use sp1_recursion_core::{
    air::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH},
    stark::{
        config::{outer_fri_config_with_blowup, BabyBearPoseidon2Outer},
        utils::sp1_dev_mode,
        RecursionAirWideDeg17,
    },
};
use sp1_recursion_program::{
    commit::PolynomialSpaceVariable, stark::RecursiveVerifierConstraintFolder,
    types::QuotientDataValues,
};

use sp1_stark::{
    air::MachineAir, Com, ShardCommitment, ShardProof, StarkGenericConfig, StarkMachine,
    StarkVerifyingKey, PROOF_MAX_NUM_PVS,
};

use crate::{
    challenger::MultiField32ChallengerVariable,
    domain::{new_coset, TwoAdicMultiplicativeCosetVariable},
    types::{RecursionShardProofVariable, TwoAdicPcsMatsVariable, TwoAdicPcsRoundVariable},
};

#[derive(Debug, Clone, Copy)]
pub struct StarkVerifierCircuit<C: Config, SC: StarkGenericConfig> {
    _phantom: PhantomData<(C, SC)>,
}

impl<C: Config, SC: StarkGenericConfig> StarkVerifierCircuit<C, SC>
where
    SC: StarkGenericConfig<
        Val = C::F,
        Challenge = C::EF,
        Domain = TwoAdicMultiplicativeCoset<C::F>,
    >,
{
    pub fn verify_shard<A, const DEGREE: usize>(
        builder: &mut Builder<C>,
        vk: &StarkVerifyingKey<SC>,
        machine: &StarkMachine<SC, A>,
        challenger: &mut MultiField32ChallengerVariable<C>,
        proof: &RecursionShardProofVariable<C>,
        chip_quotient_data: Vec<QuotientDataValues>,
        sorted_chips: Vec<String>,
        sorted_indices: Vec<usize>,
    ) where
        A: MachineAir<C::F> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
        C::F: TwoAdicField,
        C::EF: TwoAdicField,
        Com<SC>: Into<[Bn254Fr; 1]>,
        SymbolicVar<<C as Config>::N>: From<Bn254Fr>,
    {
        let RecursionShardProofVariable { commitment, opened_values, .. } = proof;

        let ShardCommitment { main_commit, permutation_commit, quotient_commit } = commitment;

        let permutation_challenges =
            (0..2).map(|_| challenger.sample_ext(builder)).collect::<Vec<_>>();

        challenger.observe_commitment(builder, *permutation_commit);

        let alpha = challenger.sample_ext(builder);

        challenger.observe_commitment(builder, *quotient_commit);

        let zeta = challenger.sample_ext(builder);

        let num_shard_chips = opened_values.chips.len();
        let mut trace_domains = Vec::new();
        let mut quotient_domains = Vec::new();

        let mut main_mats: Vec<TwoAdicPcsMatsVariable<_>> = Vec::new();
        let mut perm_mats: Vec<TwoAdicPcsMatsVariable<_>> = Vec::new();

        let mut quotient_mats = Vec::new();

        let qc_points = vec![zeta];

        let prep_mats: Vec<TwoAdicPcsMatsVariable<_>> = vk
            .chip_information
            .iter()
            .map(|(name, domain, _)| {
                let chip_idx =
                    machine.chips().iter().rposition(|chip| &chip.name() == name).unwrap();
                let index = sorted_indices[chip_idx];
                let opening = &opened_values.chips[index];

                let domain_var: TwoAdicMultiplicativeCosetVariable<_> = builder.constant(*domain);

                let mut trace_points = Vec::new();
                let zeta_next = domain_var.next_point(builder, zeta);

                trace_points.push(zeta);
                trace_points.push(zeta_next);

                let prep_values =
                    vec![opening.preprocessed.local.clone(), opening.preprocessed.next.clone()];
                TwoAdicPcsMatsVariable::<C> {
                    domain: *domain,
                    points: trace_points.clone(),
                    values: prep_values,
                }
            })
            .collect::<Vec<_>>();

        (0..num_shard_chips).for_each(|i| {
            let opening = &opened_values.chips[i];
            let log_quotient_degree = chip_quotient_data[i].log_quotient_degree;
            let domain = new_coset(builder, opening.log_degree);

            let log_quotient_size = opening.log_degree + log_quotient_degree;
            let quotient_domain =
                domain.create_disjoint_domain(builder, Usize::Const(log_quotient_size), None);

            let mut trace_points = Vec::new();
            let zeta_next = domain.next_point(builder, zeta);
            trace_points.push(zeta);
            trace_points.push(zeta_next);

            let main_values = vec![opening.main.local.clone(), opening.main.next.clone()];
            let main_mat = TwoAdicPcsMatsVariable::<C> {
                domain: TwoAdicMultiplicativeCoset { log_n: domain.log_n, shift: domain.shift },
                values: main_values,
                points: trace_points.clone(),
            };

            let perm_values =
                vec![opening.permutation.local.clone(), opening.permutation.next.clone()];
            let perm_mat = TwoAdicPcsMatsVariable::<C> {
                domain: TwoAdicMultiplicativeCoset {
                    log_n: domain.clone().log_n,
                    shift: domain.clone().shift,
                },
                values: perm_values,
                points: trace_points,
            };

            let qc_mats = quotient_domain
                .split_domains_const(builder, log_quotient_degree)
                .into_iter()
                .enumerate()
                .map(|(j, qc_dom)| TwoAdicPcsMatsVariable::<C> {
                    domain: TwoAdicMultiplicativeCoset {
                        log_n: qc_dom.clone().log_n,
                        shift: qc_dom.clone().shift,
                    },
                    values: vec![opening.quotient[j].clone()],
                    points: qc_points.clone(),
                });

            trace_domains.push(domain.clone());
            quotient_domains.push(quotient_domain.clone());
            main_mats.push(main_mat);
            perm_mats.push(perm_mat);
            quotient_mats.extend(qc_mats);
        });

        let mut rounds = Vec::new();
        let prep_commit_val: [Bn254Fr; 1] = vk.commit.clone().into();
        let prep_commit: OuterDigestVariable<C> = [builder.eval(prep_commit_val[0])];
        let prep_round = TwoAdicPcsRoundVariable { batch_commit: prep_commit, mats: prep_mats };
        let main_round = TwoAdicPcsRoundVariable { batch_commit: *main_commit, mats: main_mats };
        let perm_round =
            TwoAdicPcsRoundVariable { batch_commit: *permutation_commit, mats: perm_mats };
        let quotient_round =
            TwoAdicPcsRoundVariable { batch_commit: *quotient_commit, mats: quotient_mats };
        rounds.push(prep_round);
        rounds.push(main_round);
        rounds.push(perm_round);
        rounds.push(quotient_round);
        let config = outer_fri_config_with_blowup(log2_strict_usize(DEGREE - 1));
        verify_two_adic_pcs(builder, &config, &proof.opening_proof, challenger, rounds);

        if !sp1_dev_mode() {
            for (i, sorted_chip) in sorted_chips.iter().enumerate() {
                for chip in machine.chips() {
                    if chip.name() == *sorted_chip {
                        let values = &opened_values.chips[i];
                        let trace_domain = &trace_domains[i];
                        let quotient_domain = &quotient_domains[i];
                        let qc_domains = quotient_domain
                            .split_domains_const(builder, chip.log_quotient_degree());
                        Self::verify_constraints(
                            builder,
                            chip,
                            values,
                            proof.public_values.clone(),
                            trace_domain.clone(),
                            qc_domains,
                            zeta,
                            alpha,
                            &permutation_challenges,
                        );
                    }
                }
            }
        }
    }
}

type OuterSC = BabyBearPoseidon2Outer;
type OuterF = <BabyBearPoseidon2Outer as StarkGenericConfig>::Val;
type OuterC = OuterConfig;

pub fn build_wrap_circuit(
    wrap_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: ShardProof<OuterSC>,
) -> Vec<Constraint> {
    let outer_config = OuterSC::new();
    let outer_machine = RecursionAirWideDeg17::<OuterF>::wrap_machine(outer_config);

    let mut builder = Builder::<OuterConfig>::default();
    let mut challenger = MultiField32ChallengerVariable::new(&mut builder);

    let preprocessed_commit_val: [Bn254Fr; 1] = wrap_vk.commit.into();
    let preprocessed_commit: OuterDigestVariable<OuterC> =
        [builder.eval(preprocessed_commit_val[0])];
    challenger.observe_commitment(&mut builder, preprocessed_commit);
    let pc_start = builder.eval(wrap_vk.pc_start);
    challenger.observe(&mut builder, pc_start);

    let mut witness = Witness::default();
    template_proof.write(&mut witness);
    let proof = template_proof.read(&mut builder);

    let commited_values_digest = Bn254Fr::zero().read(&mut builder);
    builder.commit_commited_values_digest_circuit(commited_values_digest);
    let vkey_hash = Bn254Fr::zero().read(&mut builder);
    builder.commit_vkey_hash_circuit(vkey_hash);

    // Validate public values
    let mut pv_elements = Vec::new();
    for i in 0..PROOF_MAX_NUM_PVS {
        let element = builder.get(&proof.public_values, i);
        pv_elements.push(element);
    }

    let pv: &RecursionPublicValues<_> = pv_elements.as_slice().borrow();

    let one_felt: Felt<_> = builder.constant(BabyBear::one());
    // Proof must be complete. In the reduce program, this will ensure that the SP1 proof has been
    // fully accumulated.
    builder.assert_felt_eq(pv.is_complete, one_felt);

    // Convert pv.sp1_vk_digest into Bn254
    let pv_vkey_hash = babybears_to_bn254(&mut builder, &pv.sp1_vk_digest);
    // Vkey hash must match the witnessed commited_values_digest that we are committing to.
    builder.assert_var_eq(pv_vkey_hash, vkey_hash);

    // Convert pv.committed_value_digest into Bn254
    let pv_committed_values_digest_bytes: [Felt<_>; 32] =
        words_to_bytes(&pv.committed_value_digest).try_into().unwrap();
    let pv_committed_values_digest: Var<_> =
        babybear_bytes_to_bn254(&mut builder, &pv_committed_values_digest_bytes);

    // Committed values digest must match the witnessed one that we are committing to.
    builder.assert_var_eq(pv_committed_values_digest, commited_values_digest);

    let chips = outer_machine
        .shard_chips_ordered(&template_proof.chip_ordering)
        .map(|chip| chip.name())
        .collect::<Vec<_>>();

    let sorted_indices = outer_machine
        .chips()
        .iter()
        .map(|chip| template_proof.chip_ordering.get(&chip.name()).copied().unwrap_or(usize::MAX))
        .collect::<Vec<_>>();

    let chip_quotient_data = outer_machine
        .shard_chips_ordered(&template_proof.chip_ordering)
        .map(|chip| {
            let log_quotient_degree = chip.log_quotient_degree();
            QuotientDataValues { log_quotient_degree, quotient_size: 1 << log_quotient_degree }
        })
        .collect();

    let ShardCommitment { main_commit, .. } = &proof.commitment;
    challenger.observe_commitment(&mut builder, *main_commit);
    let pv_slice = proof.public_values.slice(
        &mut builder,
        Usize::Const(0),
        Usize::Const(outer_machine.num_pv_elts()),
    );
    challenger.observe_slice(&mut builder, pv_slice);

    StarkVerifierCircuit::<OuterC, OuterSC>::verify_shard::<_, 17>(
        &mut builder,
        wrap_vk,
        &outer_machine,
        &mut challenger.clone(),
        &proof,
        chip_quotient_data,
        chips,
        sorted_indices,
    );

    let zero_ext: Ext<_, _> = builder.constant(<OuterConfig as Config>::EF::zero());
    let cumulative_sum: Ext<_, _> = builder.eval(zero_ext);
    for chip in proof.opened_values.chips {
        builder.assign(cumulative_sum, cumulative_sum + chip.cumulative_sum);
    }
    builder.assert_ext_eq(cumulative_sum, zero_ext);

    // Verify the public values digest.
    let calculated_digest = builder.p2_babybear_hash(&pv_elements[0..NUM_PV_ELMS_TO_HASH]);
    let expected_digest = pv.digest;
    for (calculated_elm, expected_elm) in calculated_digest.iter().zip(expected_digest.iter()) {
        builder.assert_felt_eq(*expected_elm, *calculated_elm);
    }

    let mut backend = ConstraintCompiler::<OuterConfig>::default();
    backend.emit(builder.into_operations())
}

pub fn cycle_tracker<'a, C: Config + Debug + 'a>(
    operations: impl IntoIterator<Item = &'a DslIr<C>>,
) -> Result<Span<String, String>, SpanBuilderError> {
    let mut span_builder = SpanBuilder::new("cycle_tracker".to_string());
    for op in operations.into_iter() {
        if let DslIr::CycleTracker(name) = op {
            if span_builder.current_span.name != *name {
                span_builder.enter(name.to_owned());
            } else {
                span_builder.exit().map_err(SpanBuilderError::from)?;
            }
        } else {
            let op_dbg_str = format!("{op:?}");
            let op_name = op_dbg_str
                [..op_dbg_str.chars().take_while(|x| x.is_alphanumeric()).count()]
                .to_owned();
            span_builder.item(op_name);
        }
    }
    span_builder.finish().map_err(SpanBuilderError::from)
}

#[cfg(test)]
pub(crate) mod tests {

    use sp1_recursion_core::{cpu::Instruction, runtime::Opcode};

    pub fn basic_program<F: p3_field::PrimeField32>(
    ) -> sp1_recursion_core::runtime::RecursionProgram<F> {
        let zero = [F::zero(); 4];
        let one = [F::one(), F::zero(), F::zero(), F::zero()];
        let mut instructions = vec![Instruction::new(
            Opcode::ADD,
            F::from_canonical_u32(3),
            zero,
            one,
            F::zero(),
            F::zero(),
            false,
            true,
            "".to_string(),
        )];
        instructions.resize(
            31,
            Instruction::new(
                Opcode::ADD,
                F::from_canonical_u32(3),
                zero,
                one,
                F::zero(),
                F::zero(),
                false,
                true,
                "".to_string(),
            ),
        );
        instructions.push(Instruction::new(
            Opcode::HALT,
            F::zero(),
            zero,
            zero,
            F::zero(),
            F::zero(),
            true,
            true,
            "".to_string(),
        ));
        sp1_recursion_core::runtime::RecursionProgram::<F> { instructions, traces: vec![None] }
    }
}
