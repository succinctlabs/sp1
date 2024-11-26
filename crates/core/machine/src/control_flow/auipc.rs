use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_core_executor::{Opcode, DEFAULT_PC_INC, UNUSED_PC};
use sp1_derive::AlignedBorrow;
use sp1_stark::{air::SP1AirBuilder, Word};
use std::{borrow::Borrow, mem::size_of};

use crate::operations::BabyBearWordRangeChecker;

#[derive(Default)]
pub struct AUIPCChip;

pub const NUM_AUIPC_COLS: usize = size_of::<AUIPCColumns<u8>>();

impl<F> BaseAir<F> for AUIPCChip {
    fn width(&self) -> usize {
        NUM_AUIPC_COLS
    }
}

/// The column layout for memory.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AUIPCColumns<T> {
    /// The program counter of the instruction.
    pub pc: Word<T>,

    /// The value of the first operand.
    pub op_a_value: Word<T>,
    /// The value of the second operand.
    pub op_b_value: Word<T>,

    /// BabyBear range checker for the program counter.
    pub pc_range_checker: BabyBearWordRangeChecker<T>,

    /// The AUIPC nonce for the ADD operation.
    pub auipc_nonce: T,

    pub is_real: T,
}

impl<AB> Air<AB> for AUIPCChip
where
    AB: SP1AirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &AUIPCColumns<AB::Var> = (*local).borrow();

        builder.receive_instruction(
            local.pc.reduce::<AB>(),
            local.pc.reduce::<AB>() + AB::Expr::from_canonical_u32(DEFAULT_PC_INC),
            AB::Expr::from_canonical_u32(Opcode::AUIPC as u32),
            local.op_a_value,
            local.op_b_value,
            Word::zero::<AB>(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_real,
        );

        // Range check the pc.
        BabyBearWordRangeChecker::<AB::F>::range_check(
            builder,
            local.pc,
            local.pc_range_checker,
            local.is_real.into(),
        );

        // Verify that op_a == pc + op_b.
        builder.send_instruction(
            AB::Expr::from_canonical_u32(UNUSED_PC),
            AB::Expr::from_canonical_u32(UNUSED_PC + DEFAULT_PC_INC),
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.op_a_value,
            local.pc,
            local.op_b_value,
            AB::Expr::zero(),
            local.auipc_nonce,
            AB::Expr::zero(),
            local.is_real,
        );
    }
}
