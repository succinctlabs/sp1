use p3_air::Air;
use p3_field::extension::BinomiallyExtendable;

use sp1_core::air::MachineAir;
use sp1_core::stark::{MachineChip, StarkGenericConfig, SuperChallenge, VerifierConstraintFolder};
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::ir::{Ext, Felt, SymbolicExt, SymbolicFelt};

fn verify_constraints<SC: StarkGenericConfig, A: MachineAir<SC::Val>>(
    builder: &mut VmBuilder<SC::Val>,
    chip: MachineChip<SC, A>,
    folder: &mut VerifierConstraintFolder<
        SC::Val,
        SuperChallenge<SC::Val>,
        Felt<SC::Val>,
        Ext<SC::Val>,
        SymbolicFelt<SC::Val>,
        SymbolicExt<SC::Val>,
    >,
) where
    A: for<'a> Air<
        VerifierConstraintFolder<
            'a,
            SC::Val,
            SuperChallenge<SC::Val>,
            Felt<SC::Val>,
            Ext<SC::Val>,
            SymbolicFelt<SC::Val>,
            SymbolicExt<SC::Val>,
        >,
    >,
    SC::Val: BinomiallyExtendable<4>,
{
    chip.eval(folder);
}

fn main() {
    println!("Hello, world!");
}
