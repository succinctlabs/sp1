pub mod register;

use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_core_executor::{ByteOpcode, DEFAULT_PC_INC};
use sp1_stark::{
    air::{BaseAirBuilder, PublicValues, SP1AirBuilder, SP1_PROOF_NUM_PV_ELTS},
    Word,
};

use crate::{
    air::{MemoryAirBuilder, SP1CoreAirBuilder},
    cpu::{
        columns::{CpuCols, NUM_CPU_COLS},
        CpuChip,
    },
};

impl<AB> Air<AB> for CpuChip
where
    AB: SP1CoreAirBuilder + AirBuilderWithPublicValues,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &CpuCols<AB::Var> = (*local).borrow();
        let next: &CpuCols<AB::Var> = (*next).borrow();

        let public_values_slice: [AB::PublicVar; SP1_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| builder.public_values()[i]);
        let public_values: &PublicValues<Word<AB::PublicVar>, AB::PublicVar> =
            public_values_slice.as_slice().borrow();

        // We represent the `clk` with a 16 bit limb and a 8 bit limb.
        // The range checks for these limbs are done in `eval_shard_clk`.
        let clk =
            AB::Expr::from_canonical_u32(1u32 << 16) * local.clk_8bit_limb + local.clk_16bit_limb;

        // Program constraints.
        // SAFETY: `local.is_real` is checked to be boolean in `eval_is_real`.
        // The `pc` and `instruction` is taken from the `ProgramChip`, where these are preprocessed.
        builder.send_program(local.pc, local.instruction, local.is_real);

        // Register constraints.
        self.eval_registers::<AB>(builder, local, clk.clone());

        // Assert the shard and clk to send.  Only the memory and syscall instructions need the
        // actual shard and clk values for memory access evals.
        // SAFETY: The usage of `builder.if_else` requires `is_memory + is_syscall` to be boolean.
        // The correctness of `is_memory` and `is_syscall` will be checked in the opcode specific chips.
        // In these correct cases, `is_memory + is_syscall` will be always boolean.
        let expected_shard_to_send =
            builder.if_else(local.is_memory + local.is_syscall, local.shard, AB::Expr::zero());
        let expected_clk_to_send =
            builder.if_else(local.is_memory + local.is_syscall, clk.clone(), AB::Expr::zero());
        builder.when(local.is_real).assert_eq(local.shard_to_send, expected_shard_to_send);
        builder.when(local.is_real).assert_eq(local.clk_to_send, expected_clk_to_send);

        // Send the instruction.
        // SAFETY: `local.is_real` is checked to be boolean in `eval_is_real`.
        // The `shard`, `clk`, `pc` are constrained throughout the CpuChip.
        // The `local.instruction.opcode`, `local.instruction.op_a_0` are from the ProgramChip.
        // The `local.op_b_val()` and `local.op_c_val()` are constrained in `eval_registers` in the CpuChip.
        // Therefore, opcode specific chips that will receive this instruction need to the following.
        // - For an instruction with a valid opcode, exactly one opcode specific chip can receive the instruction.
        // - The `next_pc`, `num_extra_cycles`, `op_a_val`, `op_a_immutable`, `is_memory`, `is_syscall`, `is_halt` are constrained correctly.
        // Note that in this case, `shard_to_send` and `clk_to_send` will be correctly constrained as well.
        // If `instruction.op_a_0 == 1`, then `eval_registers` enforces `op_a_val() == 0`.
        // Therefore, in this case, `op_a_val` doesn't need to be constrained in the opcode specific chips.
        builder.send_instruction(
            local.shard_to_send,
            local.clk_to_send,
            local.pc,
            local.next_pc,
            local.num_extra_cycles,
            local.instruction.opcode,
            local.op_a_val(),
            local.op_b_val(),
            local.op_c_val(),
            local.instruction.op_a_0,
            local.op_a_immutable,
            local.is_memory,
            local.is_syscall,
            local.is_halt,
            local.is_real,
        );

        // Check that the shard and clk is updated correctly.
        self.eval_shard_clk(builder, local, next, public_values, clk.clone());

        // Check that the pc is updated correctly.
        self.eval_pc(builder, local, next, public_values);

        // Check that the is_real flag is correct.
        self.eval_is_real(builder, local, next);

        // Check that when `is_real=0` that all flags that send interactions are zero.
        let not_real = AB::Expr::one() - local.is_real;
        builder.when(not_real.clone()).assert_zero(AB::Expr::one() - local.instruction.imm_b);
        builder.when(not_real.clone()).assert_zero(AB::Expr::one() - local.instruction.imm_c);
        builder.when(not_real.clone()).assert_zero(AB::Expr::one() - local.is_syscall);
    }
}

impl CpuChip {
    /// Constraints related to the shard and clk.
    ///
    /// This method ensures that all of the shard values are the same and that the clk starts at 0
    /// and is transitioned appropriately.  It will also check that shard values are within 16 bits
    /// and clk values are within 24 bits.  Those range checks are needed for the memory access
    /// timestamp check, which assumes those values are within 2^24.  See
    /// [`MemoryAirBuilder::verify_mem_access_ts`].
    pub(crate) fn eval_shard_clk<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        public_values: &PublicValues<Word<AB::PublicVar>, AB::PublicVar>,
        clk: AB::Expr,
    ) {
        // Verify the public value's shard.
        builder.when(local.is_real).assert_eq(public_values.execution_shard, local.shard);

        // Verify that all shard values are the same.
        builder.when_transition().when(next.is_real).assert_eq(local.shard, next.shard);

        // Verify that the shard value is within 16 bits.
        // SAFETY: `local.is_real` is checked to be boolean in `eval_is_real`.
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            local.shard,
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_real,
        );

        // Verify that the first row has a clk value of 0.
        builder.when_first_row().assert_zero(clk.clone());

        // We already assert that `local.clk < 2^24`. `num_extra_cycles` is an entry of a word and
        // therefore less than `2^8`, this means that the sum cannot overflow in a 31 bit field.
        // The default clk increment is also `4`, equal to `DEFAULT_PC_INC`.
        let expected_next_clk =
            clk.clone() + AB::Expr::from_canonical_u32(DEFAULT_PC_INC) + local.num_extra_cycles;

        let next_clk =
            AB::Expr::from_canonical_u32(1u32 << 16) * next.clk_8bit_limb + next.clk_16bit_limb;
        builder.when_transition().when(next.is_real).assert_eq(expected_next_clk, next_clk);

        // Range check that the clk is within 24 bits using it's limb values.
        // SAFETY: `local.is_real` is checked to be boolean in `eval_is_real`.
        builder.eval_range_check_24bits(
            clk,
            local.clk_16bit_limb,
            local.clk_8bit_limb,
            local.is_real,
        );
    }

    /// Constraints related to the pc for non jump, branch, and halt instructions.
    ///
    /// The function will verify that the pc increments by 4 for all instructions except branch,
    /// jump and halt instructions. Also, it ensures that the pc is carried down to the last row
    /// for non-real rows.
    pub(crate) fn eval_pc<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        public_values: &PublicValues<Word<AB::PublicVar>, AB::PublicVar>,
    ) {
        // Verify the public value's start pc.
        builder.when_first_row().assert_eq(public_values.start_pc, local.pc);

        // Verify that the next row's `pc` is the current row's `next_pc`.
        builder.when_transition().when(next.is_real).assert_eq(local.next_pc, next.pc);

        // Verify the public value's next pc.  We need to handle two cases:
        // 1. The last real row is a transition row.
        // 2. The last real row is the last row.

        // If the last real row is a transition row, verify the public value's next pc.
        builder
            .when_transition()
            .when(local.is_real - next.is_real)
            .assert_eq(public_values.next_pc, local.next_pc);

        // If the last real row is the last row, verify the public value's next pc.
        builder.when_last_row().when(local.is_real).assert_eq(public_values.next_pc, local.next_pc);
    }

    /// Constraints related to the is_real column.
    ///
    /// This method checks that the is_real column is a boolean.  It also checks that the first row
    /// is 1 and once its 0, it never changes value.
    pub(crate) fn eval_is_real<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        // Check the is_real flag.  It should be 1 for the first row.  Once its 0, it should never
        // change value.
        builder.assert_bool(local.is_real);
        builder.when_first_row().assert_one(local.is_real);
        builder.when_transition().when_not(local.is_real).assert_zero(next.is_real);

        // If we're halting and it's a transition, then the next.is_real should be 0.
        builder.when_transition().when(local.is_halt).assert_zero(next.is_real);
    }
}

impl<F> BaseAir<F> for CpuChip {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}
