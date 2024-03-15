use p3_air::Air;
use p3_field::AbstractField;
use sp1_core::air::MachineAir;
use sp1_core::stark::{GenericVerifierConstraintFolder, MachineChip, StarkGenericConfig};
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::ir::{Ext, SymbolicExt, Var};

#[allow(clippy::type_complexity)]
#[allow(dead_code)]
fn verify_constraints<SC: StarkGenericConfig, A: MachineAir<SC::Val>>(
    builder: &mut VmBuilder<SC::Val, SC::Challenge>,
    chip: MachineChip<SC, A>,
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
    let g: Var<SC::Val> = builder.uninit();
    let zeta: Ext<SC::Val, SC::Challenge> = builder.uninit();
    let z_h: Ext<SC::Val, SC::Challenge> = builder.uninit();
    let is_first_row = z_h / (zeta - SC::Val::one());
    let is_last_row = z_h / (zeta - SC::Val::one());
    let is_transition = zeta - SC::Val::one();
    let quotient: Ext<SC::Val, SC::Challenge> = builder.uninit();
    chip.eval(&mut folder);
    let folded_constraints = folder.accumulator;
    let expected_folded_constraints = z_h * quotient;
    builder.assert_ext_eq(folded_constraints, expected_folded_constraints);
}

fn main() {
    println!("Hello, world!");
}
