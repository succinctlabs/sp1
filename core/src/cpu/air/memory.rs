use core::borrow::Borrow;

use p3_air::AirBuilder;
use p3_field::AbstractField;

use crate::air::{BaseAirBuilder, CurtaAirBuilder, Word, WordAirBuilder};
use crate::cpu::columns::{CpuCols, MemoryColumns, OpcodeSelectorCols, NUM_MEMORY_COLUMNS};
use crate::cpu::CpuChip;
use crate::memory::MemoryCols;
use crate::runtime::Opcode;

impl CpuChip {
    /// Computes whether the opcode is a memory instruction.
    pub(crate) fn is_memory_instruction<AB: CurtaAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_lb
            + opcode_selectors.is_lbu
            + opcode_selectors.is_lh
            + opcode_selectors.is_lhu
            + opcode_selectors.is_lw
            + opcode_selectors.is_sb
            + opcode_selectors.is_sh
            + opcode_selectors.is_sw
    }

    /// Computes whether the opcode is a load instruction.
    pub(crate) fn is_load_instruction<AB: CurtaAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_lb
            + opcode_selectors.is_lbu
            + opcode_selectors.is_lh
            + opcode_selectors.is_lhu
            + opcode_selectors.is_lw
    }

    /// Computes whether the opcode is a store instruction.
    pub(crate) fn is_store_instruction<AB: CurtaAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_sb + opcode_selectors.is_sh + opcode_selectors.is_sw
    }

    /// Evaluates constraints related to loading from memory.
    pub(crate) fn eval_memory_load<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ) {
        // Get the memory specific columns.
        let memory_columns: MemoryColumns<AB::Var> =
            *local.opcode_specific_columns[..NUM_MEMORY_COLUMNS].borrow();

        // Compute whether this is a load instruction.
        let is_load = self.is_load_instruction::<AB>(&local.selectors);

        self.eval_unsigned_mem_value(builder, &memory_columns, local);

        // If it's a signed operation (LB or LH), then we need verify the bit decomposition of the
        // most significant byte
        self.eval_most_sig_byte_bit_decomp(
            builder,
            &memory_columns,
            local,
            &local.unsigned_mem_val,
        );

        builder
            .when(local.selectors.is_lb + local.selectors.is_lh)
            .assert_eq(
                local.mem_value_is_neg,
                memory_columns.most_sig_byte_decomp[7],
            );

        let signed_value = Word([
            AB::Expr::zero(),
            AB::Expr::one() * local.selectors.is_lb,
            AB::Expr::one() * local.selectors.is_lh,
            AB::Expr::zero(),
        ]);

        builder.send_alu(
            Opcode::SUB.as_field::<AB::F>(),
            local.op_a_val(),
            local.unsigned_mem_val,
            signed_value,
            local.mem_value_is_neg,
        );

        builder
            .when(is_load)
            .when_not(local.mem_value_is_neg)
            .assert_word_eq(local.unsigned_mem_val, local.op_a_val());
    }

    /// Evaluates constraints related to storing to memory.
    pub(crate) fn eval_memory_store<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ) {
        let memory_columns: MemoryColumns<AB::Var> =
            *local.opcode_specific_columns[..NUM_MEMORY_COLUMNS].borrow();

        let mem_val = *memory_columns.memory_access.value();

        self.eval_offset_value_flags(builder, &memory_columns, local);

        let offset_is_zero = AB::Expr::one()
            - memory_columns.offset_is_one
            - memory_columns.offset_is_two
            - memory_columns.offset_is_three;

        let one = AB::Expr::one();

        let a_val = local.op_a_val();
        let prev_mem_val = *memory_columns.memory_access.prev_value();

        let sb_expected_stored_value = Word([
            a_val[0] * offset_is_zero.clone()
                + (one.clone() - offset_is_zero.clone()) * prev_mem_val[0],
            a_val[0] * memory_columns.offset_is_one
                + (one.clone() - memory_columns.offset_is_one) * prev_mem_val[1],
            a_val[0] * memory_columns.offset_is_two
                + (one.clone() - memory_columns.offset_is_two) * prev_mem_val[2],
            a_val[0] * memory_columns.offset_is_three
                + (one.clone() - memory_columns.offset_is_three) * prev_mem_val[3],
        ]);
        builder
            .when(local.selectors.is_sb)
            .assert_word_eq(mem_val.map(|x| x.into()), sb_expected_stored_value);

        builder
            .when(local.selectors.is_sh)
            .assert_zero(memory_columns.offset_is_one + memory_columns.offset_is_three);

        let a_is_lower_half = offset_is_zero;
        let a_is_upper_half = memory_columns.offset_is_two;
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

        builder
            .when(local.selectors.is_sw)
            .assert_word_eq(mem_val.map(|x| x.into()), a_val.map(|x| x.into()));
    }

    pub(crate) fn eval_unsigned_mem_value<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        memory_columns: &MemoryColumns<AB::Var>,
        local: &CpuCols<AB::Var>,
    ) {
        let mem_val = *memory_columns.memory_access.value();

        self.eval_offset_value_flags(builder, memory_columns, local);

        let offset_is_zero = AB::Expr::one()
            - memory_columns.offset_is_one
            - memory_columns.offset_is_two
            - memory_columns.offset_is_three;

        let mem_byte = mem_val[0] * offset_is_zero.clone()
            + mem_val[1] * memory_columns.offset_is_one
            + mem_val[2] * memory_columns.offset_is_two
            + mem_val[3] * memory_columns.offset_is_three;

        let byte_value = Word::extend_expr::<AB>(mem_byte.clone());
        builder
            .when(local.selectors.is_lb + local.selectors.is_lbu)
            .assert_word_eq(byte_value, local.unsigned_mem_val.map(|x| x.into()));

        builder
            .when(local.selectors.is_lh + local.selectors.is_lhu)
            .assert_zero(memory_columns.offset_is_one + memory_columns.offset_is_three);

        let use_lower_half = offset_is_zero;
        let use_upper_half = memory_columns.offset_is_two;
        let half_value = Word([
            use_lower_half.clone() * mem_val[0] + use_upper_half * mem_val[2],
            use_lower_half * mem_val[1] + use_upper_half * mem_val[3],
            AB::Expr::zero(),
            AB::Expr::zero(),
        ]);
        builder
            .when(local.selectors.is_lh + local.selectors.is_lhu)
            .assert_word_eq(half_value, local.unsigned_mem_val.map(|x| x.into()));

        builder
            .when(local.selectors.is_lw)
            .assert_word_eq(mem_val, local.unsigned_mem_val);
    }

    pub(crate) fn eval_most_sig_byte_bit_decomp<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        memory_columns: &MemoryColumns<AB::Var>,
        local: &CpuCols<AB::Var>,
        unsigned_mem_val: &Word<AB::Var>,
    ) {
        let mut recomposed_byte = AB::Expr::zero();
        for i in 0..8 {
            builder.assert_bool(memory_columns.most_sig_byte_decomp[i]);
            recomposed_byte +=
                memory_columns.most_sig_byte_decomp[i] * AB::Expr::from_canonical_u8(1 << i);
        }

        builder
            .when(local.selectors.is_lb)
            .assert_eq(recomposed_byte.clone(), unsigned_mem_val[0]);
        builder
            .when(local.selectors.is_lh)
            .assert_eq(recomposed_byte, unsigned_mem_val[1]);
    }

    pub(crate) fn eval_offset_value_flags<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        memory_columns: &MemoryColumns<AB::Var>,
        local: &CpuCols<AB::Var>,
    ) {
        let is_mem_op = self.is_memory_instruction::<AB>(&local.selectors);

        let offset_is_zero = AB::Expr::one()
            - memory_columns.offset_is_one
            - memory_columns.offset_is_two
            - memory_columns.offset_is_three;

        // Assert that the value flags are boolean
        builder
            .when(is_mem_op.clone())
            .assert_bool(memory_columns.offset_is_one);

        builder
            .when(is_mem_op.clone())
            .assert_bool(memory_columns.offset_is_two);

        builder
            .when(is_mem_op.clone())
            .assert_bool(memory_columns.offset_is_three);

        // Assert that only one of the value flags is true
        builder.when(is_mem_op.clone()).assert_eq(
            offset_is_zero.clone()
                + memory_columns.offset_is_one
                + memory_columns.offset_is_two
                + memory_columns.offset_is_three,
            AB::Expr::one(),
        );

        // Assert that the correct value flag is set
        builder
            .when(is_mem_op.clone() * offset_is_zero)
            .assert_eq(memory_columns.addr_offset, AB::Expr::zero());

        builder
            .when(is_mem_op.clone() * memory_columns.offset_is_one)
            .assert_eq(memory_columns.addr_offset, AB::Expr::one());

        builder
            .when(is_mem_op.clone() * memory_columns.offset_is_two)
            .assert_eq(memory_columns.addr_offset, AB::Expr::two());

        builder
            .when(is_mem_op * memory_columns.offset_is_three)
            .assert_eq(memory_columns.addr_offset, AB::Expr::from_canonical_u8(3));
    }
}
