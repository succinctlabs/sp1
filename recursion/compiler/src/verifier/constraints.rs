use std::marker::PhantomData;

use p3_air::Air;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::Field;
use sp1_core::air::MachineAir;
use sp1_core::stark::ChipOpenedValues;
use sp1_core::stark::{
    AirOpenedValues, GenericVerifierConstraintFolder, MachineChip, StarkGenericConfig,
};

use crate::prelude::{Builder, Config, Ext, Felt, SymbolicExt};
use crate::verifier::StarkGenericBuilderConfig;

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
