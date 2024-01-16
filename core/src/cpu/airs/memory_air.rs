use std::mem::transmute_copy;

use p3_air::AirBuilder;
use p3_field::AbstractField;

use crate::{
    air::{CurtaAirBuilder, Word},
    cpu::{
        cols::{
            cpu_cols::{CpuCols, MemoryColumns},
            opcode_cols::OpcodeSelectors,
        },
        CpuChip,
    },
    runtime::Opcode,
};

impl CpuChip {
    pub fn load_memory_eval<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ) {
        let memory_columns: MemoryColumns<AB::Var> =
            unsafe { transmute_copy(&local.opcode_specific_columns) };

        let is_load = local.selectors.is_lb
            + local.selectors.is_lbu
            + local.selectors.is_lh
            + local.selectors.is_lhu
            + local.selectors.is_lw;

        self.verify_unsigned_mem_value(builder, &memory_columns, local);

        // If it's a signed operation (LB or LH), then we need verify the bit decomposition of the
        // most significant byte
        self.verify_most_sig_byte_bit_decomp(
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
            AB::Expr::from_canonical_u32(Opcode::SUB as u32),
            *local.op_a_val(),
            local.unsigned_mem_val,
            signed_value,
            local.mem_value_is_neg,
        );

        builder
            .when(is_load)
            .when_not(local.mem_value_is_neg)
            .assert_word_eq(local.unsigned_mem_val, *local.op_a_val());
    }

    pub fn store_memory_eval<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ) {
        let memory_columns: MemoryColumns<AB::Var> =
            unsafe { transmute_copy(&local.opcode_specific_columns) };

        let mem_val = memory_columns.memory_access.value;

        self.verify_offset_bit_decomp(builder, &memory_columns, local);

        let index_is_zero = Self::index_is_zero::<AB>(&memory_columns);
        let index_is_one = Self::index_is_one::<AB>(&memory_columns);
        let index_is_two = Self::index_is_two::<AB>(&memory_columns);
        let index_is_three = Self::index_is_three::<AB>(&memory_columns);

        let one = AB::Expr::one();

        let a_val = *local.op_a_val();
        let prev_mem_val = memory_columns.memory_access.prev_value;

        let sb_expected_stored_value = Word([
            a_val[0] * index_is_zero.clone()
                + (one.clone() - index_is_zero.clone()) * prev_mem_val[0],
            a_val[0] * index_is_one.clone()
                + (one.clone() - index_is_one.clone()) * prev_mem_val[1],
            a_val[0] * index_is_two.clone()
                + (one.clone() - index_is_two.clone()) * prev_mem_val[2],
            a_val[0] * index_is_three.clone()
                + (one.clone() - index_is_three.clone()) * prev_mem_val[3],
        ]);
        builder
            .when(local.selectors.is_sb)
            .assert_word_eq(mem_val.map(|x| x.into()), sb_expected_stored_value);

        builder
            .when(local.selectors.is_sh)
            .assert_zero(index_is_zero + index_is_one.clone());

        let use_a_lower_half = index_is_two;
        let use_a_upper_half = index_is_three;
        let sh_expected_stored_value = Word([
            a_val[0] * use_a_lower_half.clone()
                + (one.clone() - use_a_lower_half.clone()) * prev_mem_val[0],
            a_val[1] * use_a_lower_half.clone()
                + (one.clone() - use_a_lower_half) * prev_mem_val[1],
            a_val[2] * use_a_upper_half.clone()
                + (one.clone() - use_a_upper_half.clone()) * prev_mem_val[2],
            a_val[3] * use_a_upper_half.clone()
                + (one.clone() - use_a_upper_half) * prev_mem_val[3],
        ]);
        builder
            .when(local.selectors.is_sh)
            .assert_word_eq(mem_val.map(|x| x.into()), sh_expected_stored_value);

        builder
            .when(local.selectors.is_sw)
            .assert_word_eq(mem_val.map(|x| x.into()), a_val.map(|x| x.into()));
    }

    pub fn verify_unsigned_mem_value<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        memory_columns: &MemoryColumns<AB::Var>,
        local: &CpuCols<AB::Var>,
    ) {
        let mem_val = memory_columns.memory_access.value;

        self.verify_offset_bit_decomp(builder, memory_columns, local);

        let index_is_zero = Self::index_is_zero::<AB>(memory_columns);
        let index_is_one = Self::index_is_one::<AB>(memory_columns);
        let index_is_two = Self::index_is_two::<AB>(memory_columns);
        let index_is_three = Self::index_is_three::<AB>(memory_columns);

        let mem_byte = mem_val[0] * index_is_zero.clone()
            + mem_val[1] * index_is_one.clone()
            + mem_val[2] * index_is_two.clone()
            + mem_val[3] * index_is_three.clone();

        let byte_value = AB::extend_expr_to_word(mem_byte.clone());
        builder
            .when(local.selectors.is_lb + local.selectors.is_lbu)
            .assert_word_eq(byte_value, local.unsigned_mem_val.map(|x| x.into()));

        builder
            .when(local.selectors.is_lh + local.selectors.is_lhu)
            .assert_zero(index_is_zero.clone() + index_is_one);

        let use_lower_half = index_is_two;
        let use_upper_half = index_is_three;
        let half_value = Word([
            use_lower_half.clone() * mem_val[0] + use_upper_half.clone() * mem_val[2],
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

    pub fn verify_most_sig_byte_bit_decomp<AB: CurtaAirBuilder>(
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

    pub fn verify_offset_bit_decomp<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        memory_columns: &MemoryColumns<AB::Var>,
        local: &CpuCols<AB::Var>,
    ) {
        let is_mem_op = self.is_memory_instruction::<AB>(&local.selectors);

        builder.when(is_mem_op.clone()).assert_eq(
            memory_columns.offset_bit_decomp[0] * memory_columns.offset_bit_decomp[1],
            memory_columns.offset_bits_product,
        );

        builder.when(is_mem_op.clone()).assert_eq(
            memory_columns.addr_offset,
            memory_columns.offset_bit_decomp[1] * AB::F::from_canonical_u8(2)
                + memory_columns.offset_bit_decomp[0],
        );

        builder
            .when(is_mem_op.clone())
            .assert_bool(memory_columns.offset_bit_decomp[0]);
        builder
            .when(is_mem_op)
            .assert_bool(memory_columns.offset_bit_decomp[1]);
    }

    pub fn index_is_zero<AB: CurtaAirBuilder>(memory_columns: &MemoryColumns<AB::Var>) -> AB::Expr {
        AB::Expr::one()
            - memory_columns.offset_bit_decomp[0]
            - memory_columns.offset_bit_decomp[1]
            - memory_columns.offset_bits_product
    }

    pub fn index_is_one<AB: CurtaAirBuilder>(memory_columns: &MemoryColumns<AB::Var>) -> AB::Expr {
        memory_columns.offset_bit_decomp[0] - memory_columns.offset_bits_product
    }

    pub fn index_is_two<AB: CurtaAirBuilder>(memory_columns: &MemoryColumns<AB::Var>) -> AB::Expr {
        AB::Expr::one() - memory_columns.offset_bits_product
    }

    pub fn index_is_three<AB: CurtaAirBuilder>(
        memory_columns: &MemoryColumns<AB::Var>,
    ) -> AB::Expr {
        memory_columns.offset_bits_product.into()
    }

    pub fn is_memory_instruction<AB: CurtaAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectors<AB::Var>,
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

    pub fn is_store<AB: CurtaAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectors<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_sb + opcode_selectors.is_sh + opcode_selectors.is_sw
    }
}
