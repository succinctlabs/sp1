use p3_air::Air;
use p3_commit::LagrangeSelectors;
use p3_field::{AbstractExtensionField, AbstractField, TwoAdicField};
use sp1_recursion_compiler::{
    ir::{Array, Builder, Config, Ext, ExtensionOperand, Felt, SymbolicFelt},
    prelude::SymbolicExt,
};
use sp1_recursion_program::commit::PolynomialSpaceVariable;

use sp1_recursion_program::stark::RecursiveVerifierConstraintFolder;
use sp1_stark::{
    air::MachineAir, AirOpenedValues, MachineChip, StarkGenericConfig, PROOF_MAX_NUM_PVS,
};

use crate::{
    domain::TwoAdicMultiplicativeCosetVariable,
    stark::StarkVerifierCircuit,
    types::{ChipOpenedValuesVariable, ChipOpening},
};

impl<C: Config, SC: StarkGenericConfig> StarkVerifierCircuit<C, SC>
where
    SC: StarkGenericConfig<Val = C::F, Challenge = C::EF>,
    C::F: TwoAdicField,
{
    fn eval_constraints<A>(
        builder: &mut Builder<C>,
        chip: &MachineChip<SC, A>,
        opening: &ChipOpening<C>,
        public_values: Array<C, Felt<C::F>>,
        selectors: &LagrangeSelectors<Ext<C::F, C::EF>>,
        alpha: Ext<C::F, C::EF>,
        permutation_challenges: &[Ext<C::F, C::EF>],
    ) -> Ext<C::F, C::EF>
    where
        A: for<'b> Air<RecursiveVerifierConstraintFolder<'b, C>>,
    {
        let mut unflatten = |v: &[Ext<C::F, C::EF>]| {
            v.chunks_exact(SC::Challenge::D)
                .map(|chunk| {
                    builder.eval(
                        chunk
                            .iter()
                            .enumerate()
                            .map(|(e_i, &x)| {
                                x * SymbolicExt::<C::F, C::EF>::from_f(C::EF::monomial(e_i))
                            })
                            .sum::<SymbolicExt<_, _>>(),
                    )
                })
                .collect::<Vec<Ext<_, _>>>()
        };
        let perm_opening = AirOpenedValues {
            local: unflatten(&opening.permutation.local),
            next: unflatten(&opening.permutation.next),
        };

        let mut folder_pv = Vec::new();
        for i in 0..PROOF_MAX_NUM_PVS {
            folder_pv.push(builder.get(&public_values, i));
        }

        let mut folder = RecursiveVerifierConstraintFolder::<C> {
            preprocessed: opening.preprocessed.view(),
            main: opening.main.view(),
            perm: perm_opening.view(),
            perm_challenges: permutation_challenges,
            cumulative_sum: opening.cumulative_sum,
            public_values: &folder_pv,
            is_first_row: selectors.is_first_row,
            is_last_row: selectors.is_last_row,
            is_transition: selectors.is_transition,
            alpha,
            accumulator: SymbolicExt::zero(),
            _marker: std::marker::PhantomData,
        };

        chip.eval(&mut folder);
        builder.eval(folder.accumulator)
    }

    fn recompute_quotient(
        builder: &mut Builder<C>,
        opening: &ChipOpening<C>,
        qc_domains: Vec<TwoAdicMultiplicativeCosetVariable<C>>,
        zeta: Ext<C::F, C::EF>,
    ) -> Ext<C::F, C::EF> {
        let zps = qc_domains
            .iter()
            .enumerate()
            .map(|(i, domain)| {
                let (zs, zinvs) = qc_domains
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, other_domain)| {
                        // Calculate: other_domain.zp_at_point(zeta)
                        //     * other_domain.zp_at_point(domain.first_point()).inverse()
                        let first_point = domain.first_point(builder);
                        let z = other_domain.zp_at_point_f(builder, first_point);
                        (
                            other_domain.zp_at_point(builder, zeta).to_operand().symbolic(),
                            z.inverse(),
                        )
                    })
                    .unzip::<_, _, Vec<_>, Vec<_>>();
                zs.into_iter().product::<SymbolicExt<_, _>>()
                    * zinvs.into_iter().product::<SymbolicFelt<_>>()
            })
            .collect::<Vec<SymbolicExt<_, _>>>()
            .into_iter()
            .map(|x| builder.eval(x))
            .collect::<Vec<Ext<_, _>>>();

        builder.eval(
            opening
                .quotient
                .iter()
                .enumerate()
                .map(|(ch_i, ch)| {
                    assert_eq!(ch.len(), C::EF::D);
                    ch.iter()
                        .enumerate()
                        .map(|(e_i, &c)| zps[ch_i] * C::EF::monomial(e_i) * c)
                        .sum::<SymbolicExt<_, _>>()
                })
                .sum::<SymbolicExt<_, _>>(),
        )
    }

    pub fn verify_constraints<A>(
        builder: &mut Builder<C>,
        chip: &MachineChip<SC, A>,
        opening: &ChipOpenedValuesVariable<C>,
        public_values: Array<C, Felt<C::F>>,
        trace_domain: TwoAdicMultiplicativeCosetVariable<C>,
        qc_domains: Vec<TwoAdicMultiplicativeCosetVariable<C>>,
        zeta: Ext<C::F, C::EF>,
        alpha: Ext<C::F, C::EF>,
        permutation_challenges: &[Ext<C::F, C::EF>],
    ) where
        A: MachineAir<C::F> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
    {
        builder.cycle_tracker("verify constraints");

        let opening = ChipOpening::from_variable(builder, chip, opening);
        let sels = trace_domain.selectors_at_point(builder, zeta);

        let folded_constraints = Self::eval_constraints(
            builder,
            chip,
            &opening,
            public_values,
            &sels,
            alpha,
            permutation_challenges,
        );

        let quotient: Ext<_, _> = Self::recompute_quotient(builder, &opening, qc_domains, zeta);

        builder.assert_ext_eq(folded_constraints * sels.inv_zeroifier, quotient);

        builder.cycle_tracker("verify constraints");
    }
}

#[cfg(test)]
mod tests {

    use itertools::{izip, Itertools};
    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_commit::{Pcs, PolynomialSpace};
    use sp1_recursion_compiler::{
        config::OuterConfig,
        constraints::ConstraintCompiler,
        ir::{Builder, Witness},
        prelude::ExtConst,
    };
    use sp1_recursion_core::{
        runtime::Runtime,
        stark::{config::BabyBearPoseidon2Outer, RecursionAirWideDeg3},
    };
    use sp1_recursion_gnark_ffi::PlonkBn254Prover;
    use sp1_stark::{
        Chip, Com, CpuProver, Dom, MachineProver, OpeningProof, PcsProverData, SP1CoreOpts,
        ShardCommitment, ShardProof, StarkGenericConfig, StarkMachine,
    };

    use crate::stark::{tests::basic_program, StarkVerifierCircuit};

    #[allow(clippy::type_complexity)]
    fn get_shard_data<'a, SC>(
        machine: &'a StarkMachine<SC, RecursionAirWideDeg3<SC::Val>>,
        proof: &'a ShardProof<SC>,
        challenger: &mut SC::Challenger,
    ) -> (
        Vec<&'a Chip<SC::Val, RecursionAirWideDeg3<SC::Val>>>,
        Vec<Dom<SC>>,
        Vec<Vec<Dom<SC>>>,
        Vec<SC::Challenge>,
        SC::Challenge,
        SC::Challenge,
    )
    where
        SC: StarkGenericConfig + Default,
        SC::Challenger: Clone,
        OpeningProof<SC>: Send + Sync,
        Com<SC>: Send + Sync,
        PcsProverData<SC>: Send + Sync,
        SC::Val: p3_field::PrimeField32,
        <SC as sp1_stark::StarkGenericConfig>::Val: p3_field::extension::BinomiallyExtendable<4>,
    {
        let ShardProof { commitment, opened_values, .. } = proof;

        let ShardCommitment { permutation_commit, quotient_commit, .. } = commitment;

        // Extract verification metadata.
        let pcs = machine.config().pcs();

        let permutation_challenges =
            (0..2).map(|_| challenger.sample_ext_element::<SC::Challenge>()).collect::<Vec<_>>();

        challenger.observe(permutation_commit.clone());

        let alpha = challenger.sample_ext_element::<SC::Challenge>();

        // Observe the quotient commitments.
        challenger.observe(quotient_commit.clone());

        let zeta = challenger.sample_ext_element::<SC::Challenge>();

        let chips = machine.shard_chips_ordered(&proof.chip_ordering).collect::<Vec<_>>();

        let log_degrees = opened_values.chips.iter().map(|val| val.log_degree).collect::<Vec<_>>();

        let log_quotient_degrees =
            chips.iter().map(|chip| chip.log_quotient_degree()).collect::<Vec<_>>();

        let trace_domains = log_degrees
            .iter()
            .map(|log_degree| pcs.natural_domain_for_degree(1 << log_degree))
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

        (chips, trace_domains, quotient_chunk_domains, permutation_challenges, alpha, zeta)
    }

    #[test]
    fn test_verify_constraints_whole() {
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type A = RecursionAirWideDeg3<F>;

        sp1_core_machine::utils::setup_logger();
        let program = basic_program::<F>();
        let config = SC::new();
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new_no_perm(&program);
        runtime.run().unwrap();
        let machine = A::machine(config);
        let prover = CpuProver::new(machine);
        let (pk, vk) = prover.setup(&program);
        let mut challenger = prover.config().challenger();
        let proof = prover
            .prove(&pk, vec![runtime.record], &mut challenger, SP1CoreOpts::recursion())
            .unwrap();

        let mut challenger = prover.config().challenger();
        vk.observe_into(&mut challenger);
        proof.shard_proofs.iter().for_each(|proof| {
            challenger.observe(proof.commitment.main_commit);
            challenger.observe_slice(&proof.public_values[0..prover.num_pv_elts()]);
        });

        // Run the verify inside the DSL and compare it to the calculated value.
        let mut builder = Builder::<OuterConfig>::default();

        for proof in proof.shard_proofs.into_iter().take(1) {
            let (
                chips,
                trace_domains_vals,
                quotient_chunk_domains_vals,
                permutation_challenges,
                alpha_val,
                zeta_val,
            ) = get_shard_data(prover.machine(), &proof, &mut challenger);

            for (chip, trace_domain_val, qc_domains_vals, values_vals) in izip!(
                chips.iter(),
                trace_domains_vals,
                quotient_chunk_domains_vals,
                proof.opened_values.chips.iter(),
            ) {
                let opening = builder.constant(values_vals.clone());
                let alpha = builder.eval(alpha_val.cons());
                let zeta = builder.eval(zeta_val.cons());
                let trace_domain = builder.constant(trace_domain_val);
                let pv_felts =
                    proof.public_values.iter().map(|v| builder.constant(*v)).collect_vec();
                let public_values = builder.vec(pv_felts);
                let qc_domains = qc_domains_vals
                    .iter()
                    .map(|domain| builder.constant(*domain))
                    .collect::<Vec<_>>();

                let permutation_challenges = permutation_challenges
                    .iter()
                    .map(|c| builder.eval(c.cons()))
                    .collect::<Vec<_>>();

                StarkVerifierCircuit::<_, SC>::verify_constraints::<A>(
                    &mut builder,
                    chip,
                    &opening,
                    public_values,
                    trace_domain,
                    qc_domains,
                    zeta,
                    alpha,
                    &permutation_challenges,
                )
            }
        }

        let mut backend = ConstraintCompiler::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        PlonkBn254Prover::test::<OuterConfig>(constraints.clone(), Witness::default());
    }
}
