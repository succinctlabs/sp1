use p3_air::Air;
use p3_field::extension::BinomiallyExtendable;

use sp1_core::air::MachineAir;
use sp1_core::stark::{GenericVerifierConstraintFolder, MachineChip, StarkGenericConfig};
use sp1_recursion_compiler::ir::{Ext, SymbolicExt};

#[allow(clippy::type_complexity)]
#[allow(dead_code)]
fn verify_constraints<SC: StarkGenericConfig, A: MachineAir<SC::Val>>(
    chip: MachineChip<SC, A>,
    folder: &mut GenericVerifierConstraintFolder<
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
    SC::Val: BinomiallyExtendable<4>,
{
    chip.eval(folder);
}

fn main() {
    println!("Hello, world!");
}
