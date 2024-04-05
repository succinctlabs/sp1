use p3_air::Air;
use p3_commit::LagrangeSelectors;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::TwoAdicField;
use sp1_core::air::MachineAir;
use sp1_core::air::PublicValuesDigest;
use sp1_core::air::Word;
use sp1_core::stark::AirOpenedValues;
use sp1_core::stark::{MachineChip, StarkGenericConfig};
use sp1_recursion_compiler::ir::Felt;
use sp1_recursion_compiler::ir::SymbolicFelt;
use sp1_recursion_compiler::ir::{Builder, Config, Ext};
use sp1_recursion_compiler::prelude::SymbolicExt;
use sp1_recursion_program::commit::PolynomialSpaceVariable;
use sp1_recursion_program::folder::RecursiveVerifierConstraintFolder;

use crate::domain::TwoAdicMultiplicativeCosetVariable;
use crate::stark::StarkVerifierCircuit;
use crate::types::ChipOpenedValuesVariable;
use crate::types::ChipOpening;

impl<C: Config, SC: StarkGenericConfig> StarkVerifierCircuit<C, SC>
where
    SC: StarkGenericConfig<Val = C::F, Challenge = C::EF>,
    C::F: TwoAdicField,
{
    fn eval_constraints<A>(
        builder: &mut Builder<C>,
        chip: &MachineChip<SC, A>,
        opening: &ChipOpening<C>,
        public_values: PublicValues<Word<Felt<C::F>>>,
        selectors: &LagrangeSelectors<Ext<C::F, C::EF>>,
        alpha: Ext<C::F, C::EF>,
        permutation_challenges: &[C::EF],
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
                                x * SymbolicExt::<C::F, C::EF>::Const(C::EF::monomial(e_i))
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

        let zero: Ext<SC::Val, SC::Challenge> = builder.eval(SC::Val::zero());
        let public_values: Vec<Felt<C::F>> = public_values.to_vec();
        let mut folder = RecursiveVerifierConstraintFolder {
            builder,
            preprocessed: opening.preprocessed.view(),
            main: opening.main.view(),
            perm: perm_opening.view(),
            perm_challenges: permutation_challenges,
            cumulative_sum: opening.cumulative_sum,
            public_values: &public_values,
            is_first_row: selectors.is_first_row,
            is_last_row: selectors.is_last_row,
            is_transition: selectors.is_transition,
            alpha,
            accumulator: zero,
        };

        chip.eval(&mut folder);
        folder.accumulator
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
                qc_domains
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, other_domain)| {
                        // Calculate: other_domain.zp_at_point(zeta)
                        //     * other_domain.zp_at_point(domain.first_point()).inverse()
                        let first_point = domain.first_point(builder);
                        let first_point: Ext<_, _> =
                            builder.eval(SymbolicExt::Base(SymbolicFelt::Val(first_point).into()));
                        let z = other_domain.zp_at_point(builder, first_point);
                        other_domain.zp_at_point(builder, zeta) * z.inverse()
                    })
                    .product::<SymbolicExt<_, _>>()
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
        public_values: PublicValues<Word<Felt<C::F>>>,
        trace_domain: TwoAdicMultiplicativeCosetVariable<C>,
        qc_domains: Vec<TwoAdicMultiplicativeCosetVariable<C>>,
        zeta: Ext<C::F, C::EF>,
        alpha: Ext<C::F, C::EF>,
        permutation_challenges: &[C::EF],
    ) where
        A: MachineAir<C::F> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
    {
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
    }
}

#[cfg(test)]
mod tests {

    use itertools::{izip, Itertools};
    use p3_baby_bear::DiffusionMatrixBabybear;
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_commit::{Pcs, PolynomialSpace};
    use serde::{de::DeserializeOwned, Serialize};
    use serial_test::serial;
    use sp1_core::{
        air::{PublicValuesDigest, Word},
        stark::{
            Chip, Com, Dom, LocalProver, MachineStark, OpeningProof, PcsProverData,
            ShardCommitment, ShardMainData, ShardProof, StarkGenericConfig,
        },
    };
    use sp1_recursion_compiler::{
        constraints::{gnark_ffi, ConstraintBackend},
        ir::{Builder, Felt},
        prelude::ExtConst,
        OuterConfig,
    };
    use sp1_recursion_core::{
        runtime::Runtime,
        stark::{config::BabyBearPoseidon2Outer, RecursionAir},
    };

    use crate::stark::{tests::basic_program, StarkVerifierCircuit};

    #[allow(clippy::type_complexity)]
    fn get_shard_data<'a, SC>(
        machine: &'a MachineStark<SC, RecursionAir<SC::Val>>,
        proof: &'a ShardProof<SC>,
        challenger: &mut SC::Challenger,
    ) -> (
        Vec<&'a Chip<SC::Val, RecursionAir<SC::Val>>>,
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
        ShardMainData<SC>: Serialize + DeserializeOwned,
        SC::Val: p3_field::PrimeField32,
        <SC as sp1_core::stark::StarkGenericConfig>::Val:
            p3_field::extension::BinomiallyExtendable<4>,
    {
        let ShardProof {
            commitment,
            opened_values,
            ..
        } = proof;

        let ShardCommitment {
            permutation_commit,
            quotient_commit,
            ..
        } = commitment;

        // Extract verification metadata.
        let pcs = machine.config().pcs();

        let permutation_challenges = (0..2)
            .map(|_| challenger.sample_ext_element::<SC::Challenge>())
            .collect::<Vec<_>>();

        challenger.observe(permutation_commit.clone());

        let alpha = challenger.sample_ext_element::<SC::Challenge>();

        // Observe the quotient commitments.
        challenger.observe(quotient_commit.clone());

        let zeta = challenger.sample_ext_element::<SC::Challenge>();

        let chips = machine
            .shard_chips_ordered(&proof.chip_ordering)
            .collect::<Vec<_>>();

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

        (
            chips,
            trace_domains,
            quotient_chunk_domains,
            permutation_challenges,
            alpha,
            zeta,
        )
    }

    #[test]
    #[serial]
    fn test_verify_constraints_whole() {
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type A = RecursionAir<F>;

        sp1_core::utils::setup_logger();
        let program = basic_program::<F>();
        let config = SC::new();
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabybear>::new_no_perm(&program);
        runtime.run();
        let machine = A::machine(config);
        let (pk, vk) = machine.setup(&program);
        let mut challenger = machine.config().challenger();
        let proof = machine.prove::<LocalProver<_, _>>(&pk, runtime.record, &mut challenger);

        let mut challenger = machine.config().challenger();
        challenger.observe(vk.commit);
        proof.shard_proofs.iter().for_each(|proof| {
            challenger.observe(proof.commitment.main_commit);
            challenger.observe_slice(proof.public_values.to_vec());
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
            ) = get_shard_data(&machine, &proof, &mut challenger);

            // Set up the public values.
            let mut public_values = Default::default();
            public_values.shard = builder.eval(proof.public_values.shard);
            public_values.first_row_pc = builder.eval(proof.public_values.first_row_pc);
            public_values.last_row_next_pc = builder.eval(proof.public_values.last_row_next_pc);
            public_values.exit_code = builder.eval(proof.public_values.exit_code);
            public_values.committed_value_digest = core::array::from_fn(|i| {
                let word_val = proof.public_values.committed_value_digest[i];
                Word(core::array::from_fn(|j| builder.eval(word_val[j])))
            });

            for (chip, trace_domain_val, qc_domains_vals, values_vals) in izip!(
                chips.iter(),
                trace_domains_vals,
                quotient_chunk_domains_vals,
                proof.opened_values.chips.iter(),
            ) {
                let opening = builder.eval_const(values_vals.clone());
                let alpha = builder.eval(alpha_val.cons());
                let zeta = builder.eval(zeta_val.cons());
                let trace_domain = builder.eval_const(trace_domain_val);
                let qc_domains = qc_domains_vals
                    .iter()
                    .map(|domain| builder.eval_const(*domain))
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

        let mut backend = ConstraintBackend::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        gnark_ffi::test_circuit(constraints);
    }
}
