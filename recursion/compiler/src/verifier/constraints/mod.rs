mod domain;
pub mod utils;

use p3_air::Air;
use p3_commit::LagrangeSelectors;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use sp1_core::stark::AirOpenedValues;
use sp1_core::stark::ChipOpenedValues;
use sp1_core::stark::{MachineChip, StarkGenericConfig};

use crate::prelude::Config;
use crate::prelude::ExtConst;
use crate::prelude::{Builder, Ext, SymbolicExt};

pub use domain::*;

use super::folder::RecursiveVerifierConstraintFolder;

// pub struct TwoAdicCose

impl<C: Config> Builder<C> {
    pub fn eval_constrains<SC, A>(
        &mut self,
        chip: &MachineChip<SC, A>,
        opening: &ChipOpenedValues<Ext<C::F, C::EF>>,
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
        opening: &ChipOpenedValues<Ext<C::F, C::EF>>,
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
        opening: &ChipOpenedValues<Ext<C::F, C::EF>>,
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
    #[test]
    fn test_eval_constraints() {}

    #[test]
    fn test_quotient_computation() {}
}
