use p3_air::{Air, AirBuilder};
use p3_field::AbstractField;
use sp1_stark::{air::SP1AirBuilder, Word};

use crate::{
    air::{SP1CoreAirBuilder, WordAirBuilder},
    memory::MemoryCols,
    operations::BabyBearWordRangeChecker,
};
use sp1_core_executor::{events::MemoryAccessPosition, Opcode};

use super::{columns::MemoryInstructionsColumns, MemoryInstructionsChip};

impl<AB> Air<AB> for MemoryInstructionsChip
where
    AB: SP1AirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let local = builder.local();

        self.eval_memory_address_and_access::<AB>(builder, local);
        self.eval_memory_load::<AB>(builder, local);
        self.eval_memory_store::<AB>(builder, local);

        let opcode = self.compute_opcode::<AB>(builder, local);
        self.receive_instruction(
            builder,
            opcode,
            local.op_a_value,
            local.op_b_value,
            local.op_c_value,
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_real,
        );
    }
}

impl MemoryInstructionsChip {
    /// Computes the opcode based on the instruction selectors.
    pub(crate) fn compute_opcode<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &MemoryInstructionsColumns<AB::Var>,
    ) -> AB::Expr {
        builder.assert_bool(local.is_load);
        builder.assert_bool(local.is_byte);
        builder.assert_bool(local.is_half);
        builder.assert_bool(local.is_unsigned);

        // See https://www.notion.so/succinctlabs/Idea-2-Selector-Optimizations-122e020fb42f8054a227cc80f80e5acc
        // for the derivation of this formula.
        AB::Expr::from_canonical_u32(10)
            + (AB::Expr::one() - local.is_load) * AB::Expr::from_canonical_u32(5)
            + local.is_half * AB::Expr::from_canonical_u32(2)
            + local.is_unsigned * AB::Expr::from_canonical_u32(3)
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
    ) {
        // Send to the ALU table to verify correct calculation of addr_word.
        builder.send_instruction(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.addr_word,
            local.op_b_val(),
            local.op_c_val(),
            local.addr_word_nonce,
            local.is_real,
        );

        // Range check the addr_word to be a valid babybear word.
        BabyBearWordRangeChecker::<AB::F>::range_check(
            builder,
            local.addr_word,
            local.addr_word_range_checker,
            local.is_real,
        );

        // Check that each addr_word element is a byte.
        builder.slice_range_check_u8(&local.addr_word.0, local.is_real);

        // Evaluate the addr_offset column and offset flags.
        self.eval_offset_value_flags(builder, local);

        // Assert that reduce(addr_word) == addr_aligned + addr_offset.
        builder.when(local.is_real).assert_eq::<AB::Expr, AB::Expr>(
            local.addr_aligned + local.addr_offset,
            local.addr_word.reduce::<AB>(),
        );

        // Verify that the least significant byte of addr_word - addr_offset is divisible by 4.
        let offset = [local.offset_is_one, local.offset_is_two, local.offset_is_three]
            .iter()
            .enumerate()
            .fold(AB::Expr::zero(), |acc, (index, &value)| {
                acc + AB::Expr::from_canonical_usize(index + 1) * value
            });
        let mut recomposed_byte = AB::Expr::zero();
        local.aa_least_sig_byte_decomp.iter().enumerate().for_each(|(i, value)| {
            builder.when(local.is_real).assert_bool(*value);

            recomposed_byte =
                recomposed_byte.clone() + AB::Expr::from_canonical_usize(1 << (i + 2)) * *value;
        });

        builder.when(local.is_real).assert_eq(local.addr_word[0] - offset, recomposed_byte);

        // For operations that require reading from memory (not registers), we need to read the
        // value into the memory columns.
        builder.eval_memory_access(
            local.shard,
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            local.addr_aligned,
            &local.memory_access,
            local.is_real,
        );

        // On memory load instructions, make sure that the memory value is not changed.
        builder
            .when(self.is_load_instruction::<AB>(&local.selectors))
            .assert_word_eq(*local.memory_access.value(), *local.memory_access.prev_value());
    }

    /// Evaluates constraints related to loading from memory.
    pub(crate) fn eval_memory_load<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &MemoryInstructionsColumns<AB::Var>,
    ) {
        // Get the memory specific columns.
        let memory_columns = local.opcode_specific_columns.memory();

        // Verify the unsigned_mem_value column.
        self.eval_unsigned_mem_value(builder, local);

        // If it's a signed operation (such as LB or LH), then we need verify the bit decomposition
        // of the most significant byte to get it's sign.
        self.eval_most_sig_byte_bit_decomp(builder, local, &local.unsigned_mem_val);

        // Assert that correct value of `mem_value_is_neg_not_x0`.
        builder.assert_eq(
            local.mem_value_is_neg_not_x0,
            (local.selectors.is_lb + local.selectors.is_lh)
                * memory_columns.most_sig_byte_decomp[7]
                * (AB::Expr::one() - local.instruction.op_a_0),
        );

        // When the memory value is negative and not writing to x0, use the SUB opcode to compute
        // the signed value of the memory value and verify that the op_a value is correct.
        let signed_value = Word([
            AB::Expr::zero(),
            AB::Expr::one() * local.selectors.is_lb,
            AB::Expr::one() * local.selectors.is_lh,
            AB::Expr::zero(),
        ]);
        builder.send_instruction(
            Opcode::SUB.as_field::<AB::F>(),
            local.op_a_val(),
            local.unsigned_mem_val,
            signed_value,
            local.shard,
            local.unsigned_mem_val_nonce,
            local.mem_value_is_neg_not_x0,
        );

        // Assert that correct value of `mem_value_is_pos_not_x0`.
        let mem_value_is_pos = (local.selectors.is_lb + local.selectors.is_lh)
            * (AB::Expr::one() - memory_columns.most_sig_byte_decomp[7])
            + local.selectors.is_lbu
            + local.selectors.is_lhu
            + local.selectors.is_lw;
        builder.assert_eq(
            local.mem_value_is_pos_not_x0,
            mem_value_is_pos * (AB::Expr::one() - local.instruction.op_a_0),
        );

        // When the memory value is not positive and not writing to x0, assert that op_a value is
        // equal to the unsigned memory value.
        builder
            .when(local.mem_value_is_pos_not_x0)
            .assert_word_eq(local.unsigned_mem_val, local.op_a_val());
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
            AB::Expr::one() - local.offset_is_one - local.offset_is_two - local.offset_is_three;

        // Compute the expected stored value for a SB instruction.
        let one = AB::Expr::one();
        let a_val = local.op_a_val();
        let mem_val = *local.memory_access.value();
        let prev_mem_val = *local.memory_access.prev_value();
        let sb_expected_stored_value = Word([
            a_val[0] * offset_is_zero.clone()
                + (one.clone() - offset_is_zero.clone()) * prev_mem_val[0],
            a_val[0] * local.offset_is_one + (one.clone() - local.offset_is_one) * prev_mem_val[1],
            a_val[0] * local.offset_is_two + (one.clone() - local.offset_is_two) * prev_mem_val[2],
            a_val[0] * local.offset_is_three
                + (one.clone() - local.offset_is_three) * prev_mem_val[3],
        ]);
        builder
            .when(local.selectors.is_sb)
            .assert_word_eq(mem_val.map(|x| x.into()), sb_expected_stored_value);

        // When the instruction is SH, make sure both offset one and three are off.
        builder
            .when(local.selectors.is_sh)
            .assert_zero(local.offset_is_one + local.offset_is_three);

        // When the instruction is SW, ensure that the offset is 0.
        builder.when(local.selectors.is_sw).assert_one(offset_is_zero.clone());

        // Compute the expected stored value for a SH instruction.
        let a_is_lower_half = offset_is_zero;
        let a_is_upper_half = local.offset_is_two;
        let sh_expected_stored_value = Word([
            a_val[0] * a_is_lower_half.clone()
                + (one.clone() - a_is_lower_half.clone()) * prev_mem_val[0],
            a_val[1] * a_is_lower_half.clone() + (one.clone() - a_is_lower_half) * prev_mem_val[1],
            a_val[0] * a_is_upper_half + (one.clone() - a_is_upper_half) * prev_mem_val[2],
            a_val[1] * a_is_upper_half + (one.clone() - a_is_upper_half) * prev_mem_val[3],
        ]);
        builder
            .when(local.selectors.is_sh)
            .assert_word_eq(mem_val.map(|x| x.into()), sh_expected_stored_value);

        // When the instruction is SW, just use the word without masking.
        builder
            .when(local.selectors.is_sw)
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
            AB::Expr::one() - local.offset_is_one - local.offset_is_two - local.offset_is_three;

        // Compute the byte value.
        let mem_byte = mem_val[0] * offset_is_zero.clone()
            + mem_val[1] * local.offset_is_one
            + mem_val[2] * local.offset_is_two
            + mem_val[3] * local.offset_is_three;
        let byte_value = Word::extend_expr::<AB>(mem_byte.clone());

        // When the instruction is LB or LBU, just use the lower byte.
        builder
            .when(local.selectors.is_lb + local.selectors.is_lbu)
            .assert_word_eq(byte_value, local.unsigned_mem_val.map(|x| x.into()));

        // When the instruction is LH or LHU, use the lower half.
        builder
            .when(local.selectors.is_lh + local.selectors.is_lhu)
            .assert_zero(local.offset_is_one + local.offset_is_three);

        // When the instruction is LW, ensure that the offset is zero.
        builder.when(local.selectors.is_lw).assert_one(offset_is_zero.clone());

        let use_lower_half = offset_is_zero;
        let use_upper_half = local.offset_is_two;
        let half_value = Word([
            use_lower_half.clone() * mem_val[0] + use_upper_half * mem_val[2],
            use_lower_half * mem_val[1] + use_upper_half * mem_val[3],
            AB::Expr::zero(),
            AB::Expr::zero(),
        ]);
        builder
            .when(local.selectors.is_lh + local.selectors.is_lhu)
            .assert_word_eq(half_value, local.unsigned_mem_val.map(|x| x.into()));

        // When the instruction is LW, just use the word.
        builder.when(local.selectors.is_lw).assert_word_eq(mem_val, local.unsigned_mem_val);
    }

    /// Evaluates the decomposition of the most significant byte of the memory value.
    pub(crate) fn eval_most_sig_byte_bit_decomp<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &MemoryInstructionsColumns<AB::Var>,
        unsigned_mem_val: &Word<AB::Var>,
    ) {
        let is_mem = self.is_memory_instruction::<AB>(&local.selectors);
        let mut recomposed_byte = AB::Expr::zero();
        for i in 0..8 {
            builder.when(is_mem.clone()).assert_bool(local.most_sig_byte_decomp[i]);
            recomposed_byte = recomposed_byte.clone()
                + local.most_sig_byte_decomp[i] * AB::Expr::from_canonical_u8(1 << i);
        }
        builder.when(local.selectors.is_lb).assert_eq(recomposed_byte.clone(), unsigned_mem_val[0]);
        builder.when(local.selectors.is_lh).assert_eq(recomposed_byte, unsigned_mem_val[1]);
    }

    /// Evaluates the offset value flags.
    pub(crate) fn eval_offset_value_flags<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &MemoryInstructionsColumns<AB::Var>,
    ) {
        let offset_is_zero =
            AB::Expr::one() - local.offset_is_one - local.offset_is_two - local.offset_is_three;

        // Assert that the value flags are boolean
        builder.assert_bool(local.offset_is_one);
        builder.assert_bool(local.offset_is_two);
        builder.assert_bool(local.offset_is_three);

        // Assert that only one of the value flags is true
        builder.assert_one(
            offset_is_zero.clone()
                + local.offset_is_one
                + local.offset_is_two
                + local.offset_is_three,
        );

        // Assert that the correct value flag is set
        builder.when(offset_is_zero).assert_zero(local.addr_offset);
        builder.when(local.offset_is_one).assert_one(local.addr_offset);
        builder.when(local.offset_is_two).assert_eq(local.addr_offset, AB::Expr::two());
        builder
            .when(local.offset_is_three)
            .assert_eq(local.addr_offset, AB::Expr::from_canonical_u8(3));
    }
}
