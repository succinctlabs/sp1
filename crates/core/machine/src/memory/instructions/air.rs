use std::borrow::Borrow;

use p3_air::{Air, AirBuilder};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_stark::{air::SP1AirBuilder, Word};

use crate::{
    air::{SP1CoreAirBuilder, WordAirBuilder},
    memory::MemoryCols,
    operations::{BabyBearWordRangeChecker, IsZeroOperation},
};
use sp1_core_executor::{
    events::MemoryAccessPosition, ByteOpcode, Opcode, DEFAULT_PC_INC, UNUSED_PC,
};

use super::{columns::MemoryInstructionsColumns, MemoryInstructionsChip};

impl<AB> Air<AB> for MemoryInstructionsChip
where
    AB: SP1AirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryInstructionsColumns<AB::Var> = (*local).borrow();

        // SAFETY: All selectors `is_lb`, `is_lbu`, `is_lh`, `is_lhu`, `is_lw`, `is_sb`, `is_sh`, `is_sw` are checked to be boolean.
        // Each "real" row has exactly one selector turned on, as `is_real`, the sum of the eight selectors, is boolean.
        // Therefore, the `opcode` matches the corresponding opcode.

        let is_real = local.is_lb
            + local.is_lbu
            + local.is_lh
            + local.is_lhu
            + local.is_lw
            + local.is_sb
            + local.is_sh
            + local.is_sw;

        builder.assert_bool(local.is_lb);
        builder.assert_bool(local.is_lbu);
        builder.assert_bool(local.is_lh);
        builder.assert_bool(local.is_lhu);
        builder.assert_bool(local.is_lw);
        builder.assert_bool(local.is_sb);
        builder.assert_bool(local.is_sh);
        builder.assert_bool(local.is_sw);
        builder.assert_bool(is_real.clone());
        builder.assert_bool(local.op_a_0);

        self.eval_memory_address_and_access::<AB>(builder, local, is_real.clone());
        self.eval_memory_load::<AB>(builder, local);
        self.eval_memory_store::<AB>(builder, local);

        let opcode = self.compute_opcode::<AB>(local);

        // SAFETY: This checks the following.
        // - `shard`, `clk` are correctly received from the CpuChip
        // - `next_pc = pc + 4`
        // - `num_extra_cycles = 0`
        // - `op_a_immutable = is_sb + is_sh + is_sw`, as store instruction keeps `op_a` immutable
        // - `is_memory = 1`
        // - `is_syscall = 0`
        // - `is_halt = 0`
        // `op_a_value` when the instruction is load still has to be constrained, as well as memory opcode behavior.
        builder.receive_instruction(
            local.shard,
            local.clk,
            local.pc,
            local.pc + AB::Expr::from_canonical_u32(DEFAULT_PC_INC),
            AB::Expr::zero(),
            opcode,
            local.op_a_value,
            local.op_b_value,
            local.op_c_value,
            local.op_a_0,
            local.is_sb + local.is_sh + local.is_sw,
            AB::Expr::one(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            is_real,
        );
    }
}

impl MemoryInstructionsChip {
    /// Computes the opcode based on the instruction selectors.
    pub(crate) fn compute_opcode<AB: SP1AirBuilder>(
        &self,
        local: &MemoryInstructionsColumns<AB::Var>,
    ) -> AB::Expr {
        local.is_lb * Opcode::LB.as_field::<AB::F>()
            + local.is_lbu * Opcode::LBU.as_field::<AB::F>()
            + local.is_lh * Opcode::LH.as_field::<AB::F>()
            + local.is_lhu * Opcode::LHU.as_field::<AB::F>()
            + local.is_lw * Opcode::LW.as_field::<AB::F>()
            + local.is_sb * Opcode::SB.as_field::<AB::F>()
            + local.is_sh * Opcode::SH.as_field::<AB::F>()
            + local.is_sw * Opcode::SW.as_field::<AB::F>()
    }

    /// Constrains the addr_aligned, addr_offset, and addr_word memory columns.
    ///
    /// This method will do the following:
    /// 1. Calculate that the unaligned address is correctly computed to be op_b.value + op_c.value.
    /// 2. Calculate that the address offset is address % 4.
    /// 3. Assert the validity of the aligned address given the address offset and the unaligned
    ///    address.
    pub(crate) fn eval_memory_address_and_access<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        local: &MemoryInstructionsColumns<AB::Var>,
        is_real: AB::Expr,
    ) {
        // Send to the ALU table to verify correct calculation of addr_word.
        builder.send_instruction(
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::from_canonical_u32(UNUSED_PC),
            AB::Expr::from_canonical_u32(UNUSED_PC + DEFAULT_PC_INC),
            AB::Expr::zero(),
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.addr_word,
            local.op_b_value,
            local.op_c_value,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            is_real.clone(),
        );

        // Range check the addr_word to be a valid babybear word. Note that this will also implicitly
        // do a byte range check on the most significant byte.
        BabyBearWordRangeChecker::<AB::F>::range_check(
            builder,
            local.addr_word,
            local.addr_word_range_checker,
            is_real.clone(),
        );

        // Check that the 2nd and 3rd addr_word elements are bytes. We already check the most sig
        // byte in the BabyBearWordRangeChecker, and the least sig one in the AND byte lookup below.
        builder.slice_range_check_u8(&local.addr_word.0[1..3], is_real.clone());

        // We check that `addr_word >= 32`, or `addr_word > 31` to avoid registers.
        // Check that if the most significant bytes are zero, then the least significant byte is at least 32.
        builder.send_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            AB::Expr::one(),
            AB::Expr::from_canonical_u8(31),
            local.addr_word[0],
            local.most_sig_bytes_zero.result,
        );

        // SAFETY: Check that the above interaction is only sent if one of the opcode flags is set.
        // If `is_real = 0`, then `local.most_sig_bytes_zero.result = 0`, leading to no interaction.
        // Note that when `is_real = 1`, due to `IsZeroOperation`, `local.most_sig_bytes_zero.result` is boolean.
        builder.when(local.most_sig_bytes_zero.result).assert_one(is_real.clone());

        // Check the most_sig_byte_zero flag.  Note that we can simply add up the three most significant bytes
        // and check if the sum is zero.  Those bytes are going to be byte range checked, so the only way
        // the sum is zero is if all bytes are 0.
        IsZeroOperation::<AB::F>::eval(
            builder,
            local.addr_word[1] + local.addr_word[2] + local.addr_word[3],
            local.most_sig_bytes_zero,
            is_real.clone(),
        );

        // Evaluate the addr_offset column and offset flags.
        self.eval_offset_value_flags(builder, local);

        // Assert that reduce(addr_word) == addr_aligned + addr_ls_two_bits.
        builder.when(is_real.clone()).assert_eq::<AB::Expr, AB::Expr>(
            local.addr_aligned + local.addr_ls_two_bits,
            local.addr_word.reduce::<AB>(),
        );

        // Check the correct value of addr_ls_two_bits. Note that this lookup will implicitly do a
        // byte range check on the least sig addr byte.
        builder.send_byte(
            ByteOpcode::AND.as_field::<AB::F>(),
            local.addr_ls_two_bits,
            local.addr_word[0],
            AB::Expr::from_canonical_u8(0b11),
            is_real.clone(),
        );

        // For operations that require reading from memory (not registers), we need to read the
        // value into the memory columns.
        builder.eval_memory_access(
            local.shard,
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            local.addr_aligned,
            &local.memory_access,
            is_real.clone(),
        );

        // On memory load instructions, make sure that the memory value is not changed.
        builder
            .when(local.is_lb + local.is_lbu + local.is_lh + local.is_lhu + local.is_lw)
            .assert_word_eq(*local.memory_access.value(), *local.memory_access.prev_value());
    }

    /// Evaluates constraints related to loading from memory.
    pub(crate) fn eval_memory_load<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &MemoryInstructionsColumns<AB::Var>,
    ) {
        // Verify the unsigned_mem_value column.
        self.eval_unsigned_mem_value(builder, local);

        // Assert that correct value of `mem_value_is_neg_not_x0`.
        // SAFETY: If the opcode is not `lb` or `lh`, then `is_lb + is_lh = 0`, so `mem_value_is_neg_not_x0 = 0`.
        // In the other case, `is_lb + is_lh = 1` (at most one selector is on), so `most_sig_byte` and `most_sig_bit` are correct.
        // Since `op_a_0` is known to be correct, we can conclude that `mem_value_is_neg_not_x0` is correct for all cases, including padding rows.
        builder.assert_eq(
            local.mem_value_is_neg_not_x0,
            (local.is_lb + local.is_lh) * local.most_sig_bit * (AB::Expr::one() - local.op_a_0),
        );

        // SAFETY: `is_lb + is_lh` is already constrained to be boolean.
        // This is because at most one opcode selector can be turned on.
        builder.send_byte(
            ByteOpcode::MSB.as_field::<AB::F>(),
            local.most_sig_bit,
            local.most_sig_byte,
            AB::Expr::zero(),
            local.is_lb + local.is_lh,
        );
        builder.assert_eq(
            local.most_sig_byte,
            local.is_lb * local.unsigned_mem_val[0] + local.is_lh * local.unsigned_mem_val[1],
        );

        // When the memory value is negative and not writing to x0, use the SUB opcode to compute
        // the signed value of the memory value and verify that the op_a value is correct.
        let signed_value = Word([
            AB::Expr::zero(),
            AB::Expr::one() * local.is_lb,
            AB::Expr::one() * local.is_lh,
            AB::Expr::zero(),
        ]);

        // SAFETY: As we mentioned before, `mem_value_is_neg_not_x0` is correct in all cases and boolean in all cases.
        builder.send_instruction(
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::from_canonical_u32(UNUSED_PC),
            AB::Expr::from_canonical_u32(UNUSED_PC + DEFAULT_PC_INC),
            AB::Expr::zero(),
            Opcode::SUB.as_field::<AB::F>(),
            local.op_a_value,
            local.unsigned_mem_val,
            signed_value,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.mem_value_is_neg_not_x0,
        );

        // Assert that correct value of `mem_value_is_pos_not_x0`.
        // SAFETY: If it's a store instruction or a padding row, `mem_value_is_pos = 0`.
        // If it's an unsigned instruction (LBU, LHU, LW), then `mem_value_is_pos = 1`.
        // If it's signed instruction (LB, LH), then `most_sig_bit` will be constrained correctly, and same for `mem_value_is_pos`.
        let mem_value_is_pos = (local.is_lb + local.is_lh) * (AB::Expr::one() - local.most_sig_bit)
            + local.is_lbu
            + local.is_lhu
            + local.is_lw;
        builder.assert_eq(
            local.mem_value_is_pos_not_x0,
            mem_value_is_pos * (AB::Expr::one() - local.op_a_0),
        );

        // When the memory value is not positive and not writing to x0, assert that op_a value is
        // equal to the unsigned memory value.
        builder
            .when(local.mem_value_is_pos_not_x0)
            .assert_word_eq(local.unsigned_mem_val, local.op_a_value);

        // These two cases combine for all cases where it's a load instruction and `op_a_0 == 0`.
        // Since the store instructions have `op_a_immutable = 1`, this completely constrains the `op_a`'s value.
    }

    /// Evaluates constraints related to storing to memory.
    pub(crate) fn eval_memory_store<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &MemoryInstructionsColumns<AB::Var>,
    ) {
        // Get the memory offset flags.
        self.eval_offset_value_flags(builder, local);
        // Compute the offset_is_zero flag.  The other offset flags are already constrained by the
        // method `eval_memory_address_and_access`, which is called in
        // `eval_memory_address_and_access`.
        let offset_is_zero =
            AB::Expr::one() - local.ls_bits_is_one - local.ls_bits_is_two - local.ls_bits_is_three;

        // Compute the expected stored value for a SB instruction.
        let one = AB::Expr::one();
        let a_val = local.op_a_value;
        let mem_val = *local.memory_access.value();
        let prev_mem_val = *local.memory_access.prev_value();
        let sb_expected_stored_value = Word([
            a_val[0] * offset_is_zero.clone()
                + (one.clone() - offset_is_zero.clone()) * prev_mem_val[0],
            a_val[0] * local.ls_bits_is_one
                + (one.clone() - local.ls_bits_is_one) * prev_mem_val[1],
            a_val[0] * local.ls_bits_is_two
                + (one.clone() - local.ls_bits_is_two) * prev_mem_val[2],
            a_val[0] * local.ls_bits_is_three
                + (one.clone() - local.ls_bits_is_three) * prev_mem_val[3],
        ]);
        builder
            .when(local.is_sb)
            .assert_word_eq(mem_val.map(|x| x.into()), sb_expected_stored_value);

        // When the instruction is SH, make sure both offset one and three are off.
        builder.when(local.is_sh).assert_zero(local.ls_bits_is_one + local.ls_bits_is_three);

        // When the instruction is SW, ensure that the offset is 0.
        builder.when(local.is_sw).assert_one(offset_is_zero.clone());

        // Compute the expected stored value for a SH instruction.
        let a_is_lower_half = offset_is_zero;
        let a_is_upper_half = local.ls_bits_is_two;
        let sh_expected_stored_value = Word([
            a_val[0] * a_is_lower_half.clone()
                + (one.clone() - a_is_lower_half.clone()) * prev_mem_val[0],
            a_val[1] * a_is_lower_half.clone() + (one.clone() - a_is_lower_half) * prev_mem_val[1],
            a_val[0] * a_is_upper_half + (one.clone() - a_is_upper_half) * prev_mem_val[2],
            a_val[1] * a_is_upper_half + (one.clone() - a_is_upper_half) * prev_mem_val[3],
        ]);
        builder
            .when(local.is_sh)
            .assert_word_eq(mem_val.map(|x| x.into()), sh_expected_stored_value);

        // When the instruction is SW, just use the word without masking.
        builder
            .when(local.is_sw)
            .assert_word_eq(mem_val.map(|x| x.into()), a_val.map(|x| x.into()));
    }

    /// This function is used to evaluate the unsigned memory value for the load memory
    /// instructions.
    pub(crate) fn eval_unsigned_mem_value<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &MemoryInstructionsColumns<AB::Var>,
    ) {
        let mem_val = *local.memory_access.value();

        // Compute the offset_is_zero flag.  The other offset flags are already constrained by the
        // method `eval_memory_address_and_access`, which is called in
        // `eval_memory_address_and_access`.
        let offset_is_zero =
            AB::Expr::one() - local.ls_bits_is_one - local.ls_bits_is_two - local.ls_bits_is_three;

        // Compute the byte value.
        let mem_byte = mem_val[0] * offset_is_zero.clone()
            + mem_val[1] * local.ls_bits_is_one
            + mem_val[2] * local.ls_bits_is_two
            + mem_val[3] * local.ls_bits_is_three;
        let byte_value = Word::extend_expr::<AB>(mem_byte.clone());

        // When the instruction is LB or LBU, just use the lower byte.
        builder
            .when(local.is_lb + local.is_lbu)
            .assert_word_eq(byte_value, local.unsigned_mem_val.map(|x| x.into()));

        // When the instruction is LH or LHU, ensure that offset is either zero or two.
        builder
            .when(local.is_lh + local.is_lhu)
            .assert_zero(local.ls_bits_is_one + local.ls_bits_is_three);

        // When the instruction is LW, ensure that the offset is zero.
        builder.when(local.is_lw).assert_one(offset_is_zero.clone());

        let use_lower_half = offset_is_zero;
        let use_upper_half = local.ls_bits_is_two;
        let half_value = Word([
            use_lower_half.clone() * mem_val[0] + use_upper_half * mem_val[2],
            use_lower_half * mem_val[1] + use_upper_half * mem_val[3],
            AB::Expr::zero(),
            AB::Expr::zero(),
        ]);
        builder
            .when(local.is_lh + local.is_lhu)
            .assert_word_eq(half_value, local.unsigned_mem_val.map(|x| x.into()));

        // When the instruction is LW, just use the word.
        builder.when(local.is_lw).assert_word_eq(mem_val, local.unsigned_mem_val);
    }

    /// Evaluates the offset value flags.
    pub(crate) fn eval_offset_value_flags<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &MemoryInstructionsColumns<AB::Var>,
    ) {
        let offset_is_zero =
            AB::Expr::one() - local.ls_bits_is_one - local.ls_bits_is_two - local.ls_bits_is_three;

        // Assert that the value flags are boolean
        builder.assert_bool(local.ls_bits_is_one);
        builder.assert_bool(local.ls_bits_is_two);
        builder.assert_bool(local.ls_bits_is_three);

        // Assert that only one of the value flags is true
        builder.assert_one(
            offset_is_zero.clone()
                + local.ls_bits_is_one
                + local.ls_bits_is_two
                + local.ls_bits_is_three,
        );

        // Assert that the correct value flag is set
        // SAFETY: Due to the constraints here, at most one of the four flags can be turned on (non-zero).
        // As their sum is constrained to be 1, the only possibility is that exactly one flag is on, with value 1.
        builder.when(offset_is_zero).assert_zero(local.addr_ls_two_bits);
        builder.when(local.ls_bits_is_one).assert_one(local.addr_ls_two_bits);
        builder.when(local.ls_bits_is_two).assert_eq(local.addr_ls_two_bits, AB::Expr::two());
        builder
            .when(local.ls_bits_is_three)
            .assert_eq(local.addr_ls_two_bits, AB::Expr::from_canonical_u8(3));
    }
}
