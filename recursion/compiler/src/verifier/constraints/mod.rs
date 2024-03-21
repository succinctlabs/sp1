mod domain;
mod opening;
pub mod utils;

use p3_air::Air;
use p3_commit::LagrangeSelectors;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use sp1_core::stark::AirOpenedValues;
use sp1_core::stark::{MachineChip, StarkGenericConfig};

use crate::prelude::Config;
use crate::prelude::ExtConst;
use crate::prelude::{Builder, Ext, SymbolicExt};

pub use domain::*;
pub use opening::*;

use super::folder::RecursiveVerifierConstraintFolder;

// pub struct TwoAdicCose

impl<C: Config> Builder<C> {
    pub fn eval_constrains<SC, A>(
        &mut self,
        chip: &MachineChip<SC, A>,
        opening: &ChipOpening<C>,
        selectors: &LagrangeSelectors<Ext<C::F, C::EF>>,
        alpha: Ext<C::F, C::EF>,
        permutation_challenges: &[C::EF],
    ) -> Ext<C::F, C::EF>
    where
        SC: StarkGenericConfig<Val = C::F, Challenge = C::EF>,
        A: for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
    {
        let mut unflatten = |v: &[Ext<C::F, C::EF>]| {
            v.chunks_exact(SC::Challenge::D)
                .map(|chunk| {
                    self.eval(
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

        let zero: Ext<SC::Val, SC::Challenge> = self.eval(SC::Val::zero());
        let mut folder = RecursiveVerifierConstraintFolder {
            builder: self,
            preprocessed: opening.preprocessed.view(),
            main: opening.main.view(),
            perm: perm_opening.view(),
            perm_challenges: permutation_challenges,
            cumulative_sum: opening.cumulative_sum,
            is_first_row: selectors.is_first_row,
            is_last_row: selectors.is_last_row,
            is_transition: selectors.is_transition,
            alpha,
            accumulator: zero,
        };

        chip.eval(&mut folder);
        folder.accumulator
    }

    pub fn recompute_quotient(
        &mut self,
        opening: &ChipOpening<C>,
        qc_domains: Vec<TwoAdicMultiplicativeCoset<C>>,
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
                        let first_point: Ext<_, _> = self.eval(domain.first_point());
                        self.zp_at_point(other_domain, zeta)
                            * self.zp_at_point(other_domain, first_point).inverse()
                    })
                    .product::<SymbolicExt<_, _>>()
            })
            .collect::<Vec<SymbolicExt<_, _>>>()
            .into_iter()
            .map(|x| self.eval(x))
            .collect::<Vec<Ext<_, _>>>();

        self.eval(
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

    /// Reference: `[sp1_core::stark::Verifier::verify_constraints]`
    #[allow(clippy::too_many_arguments)]
    pub fn verify_constraints<SC, A>(
        &mut self,
        chip: &MachineChip<SC, A>,
        opening: &ChipOpening<C>,
        trace_domain: TwoAdicMultiplicativeCoset<C>,
        qc_domains: Vec<TwoAdicMultiplicativeCoset<C>>,
        zeta: Ext<C::F, C::EF>,
        alpha: Ext<C::F, C::EF>,
        permutation_challenges: &[C::EF],
    ) where
        SC: StarkGenericConfig<Val = C::F, Challenge = C::EF>,
        A: for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
    {
        let sels = self.selectors_at_point(&trace_domain, zeta);

        let folded_constraints =
            self.eval_constrains::<SC, _>(chip, opening, &sels, alpha, permutation_challenges);

        let quotient: Ext<_, _> = self.recompute_quotient(opening, qc_domains, zeta);

        // Assert that the quotient times the zerofier is equal to the folded constraints.
        self.assert_ext_eq(folded_constraints * sels.inv_zeroifier, quotient);
    }
}

#[cfg(test)]
mod tests {
    use itertools::{izip, Itertools};
    use serde::{de::DeserializeOwned, Serialize};
    use sp1_core::{
        air::MachineAir,
        stark::{
            Chip, Com, Dom, MachineStark, OpeningProof, PcsProverData, RiscvAir, ShardCommitment,
            ShardMainData, ShardProof, StarkGenericConfig, Verifier,
        },
        utils::BabyBearPoseidon2,
        SP1Prover, SP1Stdin,
    };
    use sp1_recursion_core::runtime::Runtime;

    use crate::{asm::VmBuilder, prelude::ExtConst};
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_field::PrimeField32;

    use p3_commit::{Pcs, PolynomialSpace};

    #[allow(clippy::type_complexity)]
    fn get_shard_data<'a, SC>(
        machine: &'a MachineStark<SC, RiscvAir<SC::Val>>,
        proof: &ShardProof<SC>,
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
            .chips()
            .iter()
            .filter(|chip| proof.chip_ids.contains(&chip.name()))
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
        let elf = include_bytes!(
            "../../../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf"
        );

        let machine = A::machine(SC::default());
        let mut challenger = machine.config().challenger();
        let proofs = SP1Prover::prove_with_config(elf, SP1Stdin::new(), machine.config().clone())
            .unwrap()
            .proof
            .shard_proofs;
        println!("Proof generated successfully");

        proofs.iter().for_each(|proof| {
            challenger.observe(proof.commitment.main_commit);
        });

        // Run the verify inside the DSL and compare it to the calculated value.
        let mut builder = VmBuilder::<F, EF>::default();

        for proof in proofs.into_iter().take(1) {
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
                // Compute the expected folded constraints value.
                let sels_val = trace_domain_val.selectors_at_point(zeta_val);
                let folded_constraints_val = Verifier::<SC, _>::eval_constraints(
                    chip,
                    values_vals,
                    &sels_val,
                    alpha_val,
                    &permutation_challenges,
                );

                // Compute the folded constraints value in the DSL.
                let values = builder.const_chip_opening(values_vals);
                let alpha = builder.eval(alpha_val.cons());
                let zeta = builder.eval(zeta_val.cons());
                let trace_domain = builder.const_domain(&trace_domain_val);
                let sels = builder.selectors_at_point(&trace_domain, zeta);
                let folded_constraints = builder.eval_constrains::<SC, _>(
                    chip,
                    &values,
                    &sels,
                    alpha,
                    permutation_challenges.as_slice(),
                );

                // Assert that the two values are equal.
                builder.assert_ext_eq(folded_constraints, folded_constraints_val.cons());

                // Compute the expected quotient value.
                let quotient_val =
                    Verifier::<SC, A>::recompute_quotient(values_vals, &qc_domains_vals, zeta_val);

                let qc_domains = qc_domains_vals
                    .iter()
                    .map(|domain| builder.const_domain(domain))
                    .collect::<Vec<_>>();
                let quotient = builder.recompute_quotient(&values, qc_domains, zeta);

                // Assert that the two values are equal.
                builder.assert_ext_eq(quotient, quotient_val.cons());

                // Assert that the constraint-quotient relation holds.
                builder.assert_ext_eq(folded_constraints * sels.inv_zeroifier, quotient);
            }
        }

        let program = builder.compile();

        let mut runtime = Runtime::<F, EF>::new(&program);
        runtime.run();
        println!(
            "The program executed successfully, number of cycles: {}",
            runtime.clk.as_canonical_u32() / 4
        );
    }
}
