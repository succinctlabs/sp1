use crate::air::{reduce, CurtaAirBuilder, Word};
use crate::bytes::ByteOpcode;

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use core::mem::transmute;
use p3_air::Air;
use p3_air::AirBuilder;
use p3_air::BaseAir;
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::MatrixRowSlices;
use p3_util::indices_arr;
use std::mem::transmute_copy;
use valida_derive::AlignedBorrow;

use super::instruction_cols::InstructionCols;
use super::opcode_cols::{InstructionType, OpcodeSelectors};
use super::trace::CpuChip;
use crate::runtime::{AccessPosition, Opcode};

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryAccessCols<T> {
    pub value: Word<T>,
    pub prev_value: Word<T>,
    // The previous segment and timestamp that this memory access is being read from.
    pub segment: T,
    pub timestamp: T,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryColumns<T> {
    // An addr that we are reading from or writing to as a word. We are guaranteed that this does
    // not overflow the field when reduced.
    pub addr_word: Word<T>,
    pub addr_aligned: T,
    pub addr_offset: T,
    pub memory_access: MemoryAccessCols<T>,
}

pub struct BranchColumns<T> {
    pub branch_cond_val: T,

    pub a_minus_b: Word<T>, // Used for BNE opcode
    pub a_minus_b_inv: Word<T>,
}

/// An AIR table for memory accesses.
#[derive(AlignedBorrow, Default, Debug)]
#[repr(C)]
pub struct CpuCols<T> {
    /// The current segment.
    pub segment: T,
    /// The clock cycle value.
    pub clk: T,
    // /// The program counter value.
    pub pc: T,

    // Columns related to the instruction.
    pub instruction: InstructionCols<T>,
    // Selectors for the opcode.
    pub selectors: OpcodeSelectors<T>,

    // Operand values, either from registers or immediate values.
    pub op_a_access: MemoryAccessCols<T>,
    pub op_b_access: MemoryAccessCols<T>,
    pub op_c_access: MemoryAccessCols<T>,

    // This is transmuted to MemoryColumns or BNEColumns
    pub opcode_specific_columns: [T; WORKSPACE_SIZE],

    /// Selector to label whether this row is a non padded row.
    pub is_real: T,
}

pub(crate) const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();
pub(crate) const CPU_COL_MAP: CpuCols<usize> = make_col_map();

pub(crate) const WORKSPACE_SIZE: usize = size_of::<MemoryColumns<u8>>();

const fn make_col_map() -> CpuCols<usize> {
    let indices_arr = indices_arr::<NUM_CPU_COLS>();
    unsafe { transmute::<[usize; NUM_CPU_COLS], CpuCols<usize>>(indices_arr) }
}

impl CpuCols<u32> {
    pub fn from_trace_row<F: PrimeField32>(row: &[F]) -> Self {
        let sized: [u32; NUM_CPU_COLS] = row
            .iter()
            .map(|x| x.as_canonical_u32())
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();
        unsafe { transmute::<[u32; NUM_CPU_COLS], CpuCols<u32>>(sized) }
    }
}

impl<T> CpuCols<T> {
    pub fn op_a_val(&self) -> &Word<T> {
        &self.op_a_access.value
    }

    pub fn op_b_val(&self) -> &Word<T> {
        &self.op_b_access.value
    }

    pub fn op_c_val(&self) -> &Word<T> {
        &self.op_c_access.value
    }
}

impl<F> BaseAir<F> for CpuChip {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}

impl<AB> Air<AB> for CpuChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &CpuCols<AB::Var> = main.row_slice(0).borrow();
        let next: &CpuCols<AB::Var> = main.row_slice(1).borrow();

        // Dummy constraint of degree 3.
        builder.assert_eq(
            local.pc * local.pc * local.pc,
            local.pc * local.pc * local.pc,
        );

        builder.assert_bool(local.is_real);

        // Clock constraints
        builder.when_first_row().assert_one(local.clk);
        builder
            .when_transition()
            .assert_eq(local.clk + AB::F::from_canonical_u32(4), next.clk);

        // Contrain the interaction with program table
        builder.send_program(local.pc, local.instruction, local.selectors, local.is_real);

        let is_memory_instruction =
            <OpcodeSelectors<AB::Var> as InstructionType<AB>>::is_memory_instruction(
                &local.selectors,
            );
        let is_branch_instruction =
            <OpcodeSelectors<AB::Var> as InstructionType<AB>>::is_branch_instruction(
                &local.selectors,
            );
        let is_alu_instruction =
            <OpcodeSelectors<AB::Var> as InstructionType<AB>>::is_alu_instruction(&local.selectors);

        //////////////////////////////////////////

        // Constraint op_a_val, op_b_val, op_c_val
        // Constraint the op_b_val and op_c_val columns when imm_b and imm_c are true.
        builder
            .when(local.selectors.imm_b)
            .assert_word_eq(*local.op_b_val(), local.instruction.op_b);
        builder
            .when(local.selectors.imm_c)
            .assert_word_eq(*local.op_c_val(), local.instruction.op_c);

        // // We always write to the first register unless we are doing a branch_op or a store_op.
        // // The multiplicity is 1-selectors.noop-selectors.reg_0_write (the case where we're trying to write to register 0).
        builder.constraint_memory_access(
            local.segment,
            local.clk + AB::F::from_canonical_u32(AccessPosition::A as u32),
            local.instruction.op_a[0],
            local.op_a_access,
            AB::Expr::one() - local.selectors.noop - local.selectors.reg_0_write,
        );

        builder
            .when(
                <OpcodeSelectors<AB::Var> as InstructionType<AB>>::is_branch_instruction(
                    &local.selectors,
                ) + local.selectors.is_store,
            )
            .assert_word_eq(*local.op_a_val(), local.op_a_access.prev_value);

        // // We always read to register b and register c unless the imm_b or imm_c flags are set.
        // TODO: for these, we could save the "op_b_access.prev_value" column because it's always
        // a read and never a write.
        builder.constraint_memory_access(
            local.segment,
            local.clk + AB::F::from_canonical_u32(AccessPosition::B as u32),
            local.instruction.op_b[0],
            local.op_b_access,
            AB::Expr::one() - local.selectors.imm_b,
        );
        builder
            .when(AB::Expr::one() - local.selectors.imm_b)
            .assert_word_eq(*local.op_b_val(), local.op_b_access.prev_value);

        builder.constraint_memory_access(
            local.segment,
            local.clk + AB::F::from_canonical_u32(AccessPosition::C as u32),
            local.instruction.op_c[0],
            local.op_c_access,
            AB::Expr::one() - local.selectors.imm_c,
        );
        builder
            .when(AB::Expr::one() - local.selectors.imm_c)
            .assert_word_eq(*local.op_c_val(), local.op_c_access.prev_value);

        let memory_columns: MemoryColumns<AB::Var> =
            unsafe { transmute_copy(&local.opcode_specific_columns) };

        builder.constraint_memory_access(
            local.segment,
            local.clk + AB::F::from_canonical_u32(AccessPosition::Memory as u32),
            memory_columns.addr_aligned,
            memory_columns.memory_access,
            is_memory_instruction.clone(),
        );

        //////////////////////////////////////////

        // Check that local.addr_offset \in [0, WORD_SIZE) by byte range checking local.addr_offset << 6
        // and local.addr_offset.
        builder.send_byte_lookup(
            AB::Expr::from_canonical_u8(ByteOpcode::Range as u8),
            AB::Expr::zero(),
            memory_columns.addr_offset,
            memory_columns.addr_offset * AB::F::from_canonical_u8(64),
            is_memory_instruction.clone(),
        );

        // Check that reduce(addr_word) == addr_aligned + addr_offset
        builder
            .when(is_memory_instruction.clone())
            .assert_eq::<AB::Expr, AB::Expr>(
                memory_columns.addr_aligned + memory_columns.addr_offset,
                reduce::<AB>(memory_columns.addr_word),
            );

        // Check that each addr_word element is a byte
        builder.range_check_word(memory_columns.addr_word, is_memory_instruction.clone());

        // Send to the ALU table to verify correct calculation of addr_word
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            memory_columns.addr_word,
            *local.op_b_val(),
            *local.op_c_val(),
            is_memory_instruction.clone(),
        );

        //////////////////////////////////////////

        //// For branch instructions
        // TODO: lookup (clk, branch_cond_val, op_a_val, op_b_val) in the "branch" table with multiplicity branch_instruction
        // Increment the pc by 4 + op_c_val * branch_cond_val where we interpret the first result as a bool that it is.

        // builder.when(local.selectors.branch_op).assert_eq(
        //     local.pc
        //         + AB::F::from_canonical_u8(4)
        //         + reduce::<AB>(local.op_c_val) * local.branch_cond_val.0[0],
        //     next.pc,
        // );
        let branch_columns: BranchColumns<AB::Var> =
            unsafe { transmute_copy(&local.opcode_specific_columns) };

        // Check that branch_cond_val is a boolean
        builder
            .when(is_branch_instruction)
            .assert_bool(branch_columns.branch_cond_val);

        // Handle the case when opcode == BEQ
        builder
            .when(local.selectors.is_beq * branch_columns.branch_cond_val)
            .assert_word_eq(*local.op_a_val(), *local.op_b_val());

        // Handle the case when opcode == BNE

        // Check that a_minus_b == a - b
        builder.send_alu(
            AB::Expr::from_canonical_u8(Opcode::SUB as u8),
            branch_columns.a_minus_b,
            *local.op_a_val(),
            *local.op_b_val(),
            local.selectors.is_bne,
        );

        // // Check that branch_cond_val == 0 < a_minus_b
        builder.send_alu(
            AB::Expr::from_canonical_u8(Opcode::SLTU as u8),
            AB::extend_expr_to_word(branch_columns.branch_cond_val),
            AB::zero_word(),
            branch_columns.a_minus_b,
            local.selectors.is_bne,
        );

        // //// For jump instructions
        // builder
        //     .when(local.selectors.jalr + local.selectors.jal)
        //     .assert_eq(
        //         reduce::<AB>(local.op_a_val),
        //         local.pc + AB::F::from_canonical_u8(4),
        //     );
        // builder.when(local.selectors.jal).assert_eq(
        //     local.pc + AB::F::from_canonical_u8(4) + reduce::<AB>(local.op_b_val),
        //     next.pc,
        // );
        // builder.when(local.selectors.jalr).assert_eq(
        //     reduce::<AB>(local.op_b_val) + local.instruction.op_c,
        //     next.pc,
        // );

        // //// Upper immediate instructions
        // // lookup(clk, op_c_val, imm, 12) in SLT table with multiplicity AUIPC
        // builder.when(local.selectors.auipc).assert_eq(
        //     reduce::<AB>(local.op_a_val),
        //     reduce::<AB>(local.op_c_val) + local.pc,
        // );

        builder.send_alu(
            local.instruction.opcode,
            *local.op_a_val(),
            *local.op_b_val(),
            *local.op_c_val(),
            is_alu_instruction,
        );
    }
}
