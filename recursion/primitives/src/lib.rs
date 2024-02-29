extern crate alloc;

mod constants;
pub use constants::*;

pub use sp1_core::*;

#[cfg(test)]
mod tests {

    use super::*;
    use crate::air::MachineAir;
    use crate::lookup::Interaction;
    use crate::runtime::{Instruction, Opcode, Program, Runtime};
    use crate::stark::{Chip, RiscvAir};
    use crate::stark::{LocalProver, RiscvStark};
    use crate::utils::BabyBearBlake3;
    use crate::utils::{setup_logger, StarkUtils};
    use p3_air::{PairCol, VirtualPairCol};
    use p3_baby_bear::BabyBear;
    use p3_field::{Field, PrimeField32};

    fn assert_pair_col_eq(left: &PairCol, right: &PairCol) {
        match (left, right) {
            (PairCol::Main(l), PairCol::Main(r)) => assert_eq!(l, r),
            (PairCol::Preprocessed(l), PairCol::Preprocessed(r)) => assert_eq!(l, r),
            _ => panic!("Unequal column types"),
        }
    }

    fn assert_virtual_pair_col_eq<F: Field>(left: &VirtualPairCol<F>, right: &VirtualPairCol<F>) {
        assert_eq!(left.get_constant(), right.get_constant());
        for (l, r) in left
            .get_column_weights()
            .iter()
            .zip(right.get_column_weights())
        {
            assert_pair_col_eq(&l.0, &r.0);
            assert_eq!(l.1, r.1);
        }
    }

    fn assert_interaction_eq<F: Field>(left: &Interaction<F>, right: &Interaction<F>) {
        assert_virtual_pair_col_eq(&left.multiplicity, &right.multiplicity);
        assert_eq!(left.kind, right.kind);
        for (l, r) in left.values.iter().zip(right.values.iter()) {
            assert_virtual_pair_col_eq(l, r);
        }
    }

    fn assert_chips_eq<F: PrimeField32>(left: &Chip<F, RiscvAir<F>>, right: &Chip<F, RiscvAir<F>>) {
        assert_eq!(left.name(), right.name());
        assert_eq!(left.log_quotient_degree(), right.log_quotient_degree());
        for (l, r) in left.sends().iter().zip(right.sends().iter()) {
            assert_interaction_eq(l, r);
        }
        for (l, r) in left.receives().iter().zip(right.receives().iter()) {
            assert_interaction_eq(l, r);
        }
    }

    #[test]
    fn test_constant_gen() {
        let config = BabyBearBlake3::new();
        let machine = RiscvStark::<BabyBearBlake3>::new(config);

        for (chip, const_chip) in machine.chips().iter().zip(RISCV_STARK.chips()) {
            assert_chips_eq(chip, const_chip);
        }
    }

    #[test]
    fn test_const_add_verify() {
        setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::<BabyBear>::new(program);
        runtime.run();

        let config = BabyBearBlake3::new();

        let machine = RiscvStark::new(config);
        let (pk, vk) = machine.setup(runtime.program.as_ref());
        let mut challenger = machine.config().challenger();
        let proof = machine.prove::<LocalProver<_>>(&pk, runtime.record, &mut challenger);

        let mut challenger = machine.config().challenger();

        RISCV_STARK
            .verify(&vk, &proof, &mut challenger)
            .expect("verification failed");
    }
}
