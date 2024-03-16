use p3_air::Air;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use sp1_core::air::MachineAir;
use sp1_core::stark::ChipOpenedValues;
use sp1_core::stark::{GenericVerifierConstraintFolder, MachineChip, StarkGenericConfig};
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::ir::{Ext, Felt, SymbolicExt};

#[allow(clippy::type_complexity)]
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
#[allow(unused_variables)]
fn verify_constraints<SC: StarkGenericConfig, A: MachineAir<SC::Val>>(
    builder: &mut VmBuilder<SC::Val, SC::Challenge>,
    chip: MachineChip<SC, A>,
    opening: ChipOpenedValues<SC::Challenge>,
    g: Felt<SC::Val>,
    zeta: Ext<SC::Val, SC::Challenge>,
    alpha: Ext<SC::Val, SC::Challenge>,
    permutation_challenges: &[Ext<SC::Val, SC::Challenge>],
    mut folder: GenericVerifierConstraintFolder<
        SC::Val,
        SC::Challenge,
        Ext<SC::Val, SC::Challenge>,
        SymbolicExt<SC::Val, SC::Challenge>,
    >,
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
    let is_first_row = builder.eval(z_h / (zeta - SC::Val::one()));
    let is_last_row = builder.eval(z_h / (zeta - g_inv));
    let is_transition = builder.eval(zeta - g_inv);
    folder.is_first_row = is_first_row;
    folder.is_last_row = is_last_row;
    folder.is_transition = is_transition;

    let monomials = (0..SC::Challenge::D)
        .map(SC::Challenge::monomial)
        .collect::<Vec<_>>();

    let quotient_parts = opening
        .quotient
        .chunks_exact(SC::Challenge::D)
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

    // TODO: FIX.
    // folder.perm_challenges = permutation_challenges.to_vec();

    chip.eval(&mut folder);
    let folded_constraints = folder.accumulator;
    let expected_folded_constraints = z_h * quotient;
    builder.assert_ext_eq(folded_constraints, expected_folded_constraints);
}

fn main() {
    println!("Hello, world!");
}
