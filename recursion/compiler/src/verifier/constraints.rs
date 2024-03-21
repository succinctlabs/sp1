use p3_air::Air;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use sp1_core::air::MachineAir;
use sp1_core::stark::ChipOpenedValues;
use sp1_core::stark::{AirOpenedValues, MachineChip, StarkGenericConfig};

use crate::ir::{Builder, Config, Ext, Felt, SymbolicExt};

use super::folder::RecursiveVerifierConstraintFolder;

impl<C: Config> Builder<C> {
    pub fn const_opened_values(
        &mut self,
        opened_values: &AirOpenedValues<C::EF>,
    ) -> AirOpenedValues<Ext<C::F, C::EF>> {
        AirOpenedValues::<Ext<C::F, C::EF>> {
            local: opened_values
                .local
                .iter()
                .map(|s| self.eval(SymbolicExt::Const(*s)))
                .collect(),
            next: opened_values
                .next
                .iter()
                .map(|s| self.eval(SymbolicExt::Const(*s)))
                .collect(),
        }
    }

    pub fn verify_constraints<SC, A>(
        &mut self,
        chip: &MachineChip<SC, A>,
        opening: &ChipOpenedValues<SC::Challenge>,
        g: Felt<SC::Val>,
        zeta: Ext<SC::Val, SC::Challenge>,
        alpha: Ext<SC::Val, SC::Challenge>,
    ) where
        SC: StarkGenericConfig,
        C: Config<F = SC::Val, EF = SC::Challenge>,
        A: MachineAir<SC::Val> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
    {
        let g_inv: Felt<SC::Val> = self.eval(g.inverse());
        let z_h: Ext<SC::Val, SC::Challenge> = self.exp_power_of_2(zeta, opening.log_degree);
        let one: Ext<SC::Val, SC::Challenge> = self.eval(SC::Val::one());
        let is_first_row = self.eval(z_h / (zeta - one));
        let is_last_row = self.eval(z_h / (zeta - g_inv));
        let is_transition = self.eval(zeta - g_inv);

        let preprocessed = self.const_opened_values(&opening.preprocessed);
        let main = self.const_opened_values(&opening.main);
        let perm = self.const_opened_values(&opening.permutation);

        let zero: Ext<SC::Val, SC::Challenge> = self.eval(SC::Val::zero());
        let cumulative_sum = self.eval(SC::Val::zero());
        let mut folder = RecursiveVerifierConstraintFolder {
            builder: self,
            preprocessed: preprocessed.view(),
            main: main.view(),
            perm: perm.view(),
            perm_challenges: &[SC::Challenge::zero(), SC::Challenge::zero()],
            cumulative_sum,
            is_first_row,
            is_last_row,
            is_transition,
            alpha,
            accumulator: zero,
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

        chip.eval(&mut folder);
        let folded_constraints = folder.accumulator;

        let mut zeta_powers = zeta;
        let quotient: Ext<SC::Val, SC::Challenge> = self.eval(SC::Val::zero());
        let quotient_expr: SymbolicExt<SC::Val, SC::Challenge> = quotient.into();
        for quotient_part in quotient_parts {
            zeta_powers = self.eval(zeta_powers * zeta);
            self.assign(quotient, zeta_powers * quotient_part);
        }
        let quotient: Ext<SC::Val, SC::Challenge> = self.eval(quotient_expr);

        let expected_folded_constraints = z_h * quotient;
        self.assert_ext_eq(folded_constraints, expected_folded_constraints);
    }
}
