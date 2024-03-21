mod types;
pub mod utils;

use p3_air::Air;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::Field;
use sp1_core::air::MachineAir;
use sp1_core::stark::ChipOpenedValues;
use sp1_core::stark::{GenericVerifierConstraintFolder, MachineChip, StarkGenericConfig};
use std::marker::PhantomData;

use crate::prelude::Config;
use crate::prelude::{Builder, Ext, Felt, SymbolicExt};
use crate::verifier::StarkGenericBuilderConfig;

pub use types::*;

use super::folder::RecursiveVerifierConstraintFolder;

// pub struct TwoAdicCose

impl<C: Config> Builder<C> {
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

        let zero: Ext<SC::Val, SC::Challenge> = self.eval(SC::Val::zero());
        let cumulative_sum = self.eval(SC::Val::zero());
        let mut folder = RecursiveVerifierConstraintFolder {
            builder: self,
            preprocessed: opening.preprocessed.view(),
            main: opening.main.view(),
            perm: opening.permutation.view(),
            perm_challenges: permutation_challenges,
            cumulative_sum,
            is_first_row: sels.is_first_row,
            is_last_row: sels.is_last_row,
            is_transition: sels.is_transition,
            alpha,
            accumulator: zero,
        };

        chip.eval(&mut folder);
        let folded_constraints = folder.accumulator;

        // let quotient = opening
        // .quotient
        // .iter()
        // .enumerate()
        // .map(|(ch_i, ch)| {
        //     assert_eq!(ch.len(), SC::Challenge::D);
        //     ch.iter()
        //         .enumerate()
        //         .map(|(e_i, &c)| zps[ch_i] * SC::Challenge::monomial(e_i) * c)
        //         .sum::<SC::Challenge>()
        // })
        // .sum::<SC::Challenge>();
    }
}

pub fn verify_constraints<N: Field, SC: StarkGenericConfig + Clone, A: MachineAir<SC::Val>>(
    builder: &mut Builder<StarkGenericBuilderConfig<N, SC>>,
    chip: &MachineChip<SC, A>,
    opening: &ChipOpenedValues<SC::Challenge>,
    g: Felt<SC::Val>,
    zeta: Ext<SC::Val, SC::Challenge>,
    alpha: Ext<SC::Val, SC::Challenge>,
) where
    A: for<'a> Air<
        GenericVerifierConstraintFolder<
            'a,
            SC::Val,
            SC::Challenge,
            Ext<SC::Val, SC::Challenge>,
            SymbolicExt<SC::Val, SC::Challenge>,
        >,
    >,
{
    let g_inv: Felt<SC::Val> = builder.eval(g / SC::Val::one());
    let z_h: Ext<SC::Val, SC::Challenge> = builder.exp_power_of_2(zeta, opening.log_degree);
    let one: Ext<SC::Val, SC::Challenge> = builder.eval(SC::Val::one());
    let is_first_row = builder.eval(z_h / (zeta - one));
    let is_last_row = builder.eval(z_h / (zeta - g_inv));
    let is_transition = builder.eval(zeta - g_inv);

    let preprocessed = builder.const_opened_values(&opening.preprocessed);
    let main = builder.const_opened_values(&opening.main);
    let perm = builder.const_opened_values(&opening.permutation);

    let zero: Ext<SC::Val, SC::Challenge> = builder.eval(SC::Val::zero());
    let zero_expr: SymbolicExt<SC::Val, SC::Challenge> = zero.into();
    let mut folder = GenericVerifierConstraintFolder::<
        SC::Val,
        SC::Challenge,
        Ext<SC::Val, SC::Challenge>,
        SymbolicExt<SC::Val, SC::Challenge>,
    > {
        preprocessed: preprocessed.view(),
        main: main.view(),
        perm: perm.view(),
        perm_challenges: &[SC::Challenge::zero(), SC::Challenge::zero()],
        cumulative_sum: builder.eval(SC::Val::zero()),
        is_first_row,
        is_last_row,
        is_transition,
        alpha,
        accumulator: zero_expr,
        _marker: PhantomData,
    };

    let monomials = (0..SC::Challenge::D)
        .map(SC::Challenge::monomial)
        .collect::<Vec<_>>();

    let quotient_parts = opening
        .quotient
        .iter()
        .map(|chunk| {
            chunk
                .iter()
                .zip(monomials.iter())
                .map(|(x, m)| *x * *m)
                .sum()
        })
        .collect::<Vec<SC::Challenge>>();

    let mut zeta_powers = zeta;
    let quotient: Ext<SC::Val, SC::Challenge> = builder.eval(SC::Val::zero());
    let quotient_expr: SymbolicExt<SC::Val, SC::Challenge> = quotient.into();
    for quotient_part in quotient_parts {
        zeta_powers = builder.eval(zeta_powers * zeta);
        builder.assign(quotient, zeta_powers * quotient_part);
    }
    let quotient: Ext<SC::Val, SC::Challenge> = builder.eval(quotient_expr);
    folder.alpha = alpha;

    chip.eval(&mut folder);
    let folded_constraints = folder.accumulator;
    let expected_folded_constraints = z_h * quotient;
    builder.assert_ext_eq(folded_constraints, expected_folded_constraints);
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_eval_constraints() {}

    #[test]
    fn test_quotient_computation() {}
}
