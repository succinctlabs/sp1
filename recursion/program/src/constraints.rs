use p3_air::Air;
use p3_commit::LagrangeSelectors;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::TwoAdicField;
use sp1_core::air::MachineAir;
use sp1_core::stark::AirOpenedValues;
use sp1_core::stark::PROOF_MAX_NUM_PVS;
use sp1_core::stark::{MachineChip, StarkGenericConfig};
use sp1_recursion_compiler::ir::Array;
use sp1_recursion_compiler::ir::Felt;
use sp1_recursion_compiler::prelude::Config;
use sp1_recursion_compiler::prelude::ExtConst;
use sp1_recursion_compiler::prelude::{Builder, Ext, SymbolicExt};

use crate::commit::PolynomialSpaceVariable;
use crate::fri::TwoAdicMultiplicativeCosetVariable;
use crate::stark::RecursiveVerifierConstraintFolder;
use crate::stark::StarkVerifier;
use crate::types::ChipOpenedValuesVariable;
use crate::types::ChipOpening;

impl<C: Config, SC: StarkGenericConfig> StarkVerifier<C, SC>
where
    SC: StarkGenericConfig<Val = C::F, Challenge = C::EF>,
    C::F: TwoAdicField,
{
    fn eval_constrains<A>(
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
                            .map(|(e_i, &x)| x * C::EF::monomial(e_i).cons())
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
                qc_domains
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, other_domain)| {
                        let first_point: Ext<_, _> = builder.eval(domain.first_point());
                        other_domain.zp_at_point(builder, zeta)
                            * other_domain.zp_at_point(builder, first_point).inverse()
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

    /// Reference: [sp1_core::stark::Verifier::verify_constraints]
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
        let opening = ChipOpening::from_variable(builder, chip, opening);
        let sels = trace_domain.selectors_at_point(builder, zeta);

        let folded_constraints = Self::eval_constrains(
            builder,
            chip,
            &opening,
            public_values,
            &sels,
            alpha,
            permutation_challenges,
        );

        let quotient: Ext<_, _> = Self::recompute_quotient(builder, &opening, qc_domains, zeta);

        // Assert that the quotient times the zerofier is equal to the folded constraints.
        builder.assert_ext_eq(folded_constraints * sels.inv_zeroifier, quotient);
    }
}

#[cfg(test)]
mod tests {
    use itertools::{izip, Itertools};
    use rand::{thread_rng, Rng};
    use serde::{de::DeserializeOwned, Serialize};
    use sp1_core::{
        io::SP1Stdin,
        runtime::Program,
        stark::{
            Chip, Com, Dom, OpeningProof, PcsProverData, RiscvAir, ShardCommitment, ShardMainData,
            ShardProof, StarkGenericConfig, StarkMachine,
        },
        utils::{BabyBearPoseidon2, SP1CoreOpts},
    };
    use sp1_recursion_core::stark::utils::{run_test_recursion, TestConfig};

    use p3_challenger::{CanObserve, FieldChallenger};
    use sp1_recursion_compiler::{asm::AsmBuilder, ir::Felt, prelude::ExtConst};

    use p3_commit::{Pcs, PolynomialSpace};

    use crate::stark::StarkVerifier;

    #[allow(clippy::type_complexity)]
    fn get_shard_data<'a, SC>(
        machine: &'a StarkMachine<SC, RiscvAir<SC::Val>>,
        proof: &'a ShardProof<SC>,
        challenger: &mut SC::Challenger,
    ) -> (
        Vec<&'a Chip<SC::Val, RiscvAir<SC::Val>>>,
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
    fn test_verify_constraints() {
        type SC = BabyBearPoseidon2;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type A = RiscvAir<F>;

        // Generate a dummy proof.
        sp1_core::utils::setup_logger();
        let elf = include_bytes!("../../../tests/fibonacci/elf/riscv32im-succinct-zkvm-elf");

        let machine = A::machine(SC::default());
        let (_, vk) = machine.setup(&Program::from(elf));
        let mut challenger = machine.config().challenger();
        let (proof, _) = sp1_core::utils::prove(
            Program::from(elf),
            &SP1Stdin::new(),
            SC::default(),
            SP1CoreOpts::default(),
        )
        .unwrap();
        machine.verify(&vk, &proof, &mut challenger).unwrap();

        println!("Proof generated and verified successfully");
        let mut challenger = machine.config().challenger();
        vk.observe_into(&mut challenger);
        proof.shard_proofs.iter().for_each(|proof| {
            challenger.observe(proof.commitment.main_commit);
            challenger.observe_slice(&proof.public_values[0..machine.num_pv_elts()]);
        });

        // Run the verify inside the DSL and compare it to the calculated value.
        let mut builder = AsmBuilder::<F, EF>::default();

        #[allow(clippy::never_loop)]
        for proof in proof.shard_proofs.into_iter().take(1) {
            let (
                chips,
                trace_domains_vals,
                quotient_chunk_domains_vals,
                permutation_challenges,
                alpha_val,
                zeta_val,
            ) = get_shard_data(&machine, &proof, &mut challenger);

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
                let public_values = builder.constant(proof.public_values.clone());

                let qc_domains = qc_domains_vals
                    .iter()
                    .map(|domain| builder.constant(*domain))
                    .collect::<Vec<_>>();

                let permutation_challenges = permutation_challenges
                    .iter()
                    .map(|c| builder.eval(c.cons()))
                    .collect::<Vec<_>>();

                StarkVerifier::<_, SC>::verify_constraints::<A>(
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
            break;
        }
        builder.halt();

        let program = builder.compile_program();
        run_test_recursion(program, None, TestConfig::All);
    }

    #[test]
    fn test_exp_reverse_bit_len_fast() {
        type SC = BabyBearPoseidon2;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;

        let mut rng = thread_rng();

        // Initialize a builder.
        let mut builder = AsmBuilder::<F, EF>::default();

        // Get a random var with `NUM_BITS` bits.
        let x_val: F = rng.gen();

        // Materialize the number as a var
        let x_felt: Felt<_> = builder.eval(x_val);
        let x_bits = builder.num2bits_f(x_felt);

        let result = builder.exp_reverse_bits_len_fast(x_felt, &x_bits, 5);
        let expected_val = builder.exp_reverse_bits_len(x_felt, &x_bits, 5);

        builder.assert_felt_eq(expected_val, result);
        builder.halt();

        let program = builder.compile_program();

        run_test_recursion(program, None, TestConfig::All);
    }
}
