use crate::air::{reduce, AirConstraint, AirVariable, Bool, Word};
use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};
use p3_air::{AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_matrix::MatrixRowSlices;
use p3_util::indices_arr;
use valida_derive::AlignedBorrow;

#[derive(AlignedBorrow, Default)]
#[repr(C)]
pub struct OpcodeSelectors<T> {
    // // Whether op_b is an immediate value.
    pub imm_b: T,
    // Whether op_c is an immediate value.
    pub imm_c: T,
    // Whether this is a register instruction.
    pub register_instruction: T,
    // Whether this is an immediate instruction.
    pub immediate_instruction: T,
    // Whether this is a load instruction.
    pub load_instruction: T,
    // Whether this is a store instruction.
    pub store_instruction: T,
    // Whether this is a branch instruction.
    pub branch_instruction: T,
    // Whether this is a jump instruction.
    pub jump_instruction: T,
    // Whether this is a system instruction.
    pub system_instruction: T,
    // Whether this is a multiply instruction.
    pub multiply_instruction: T,
    // // Selectors for load/store instructions and their types.
    pub byte: Bool<T>,
    pub half: Bool<T>,
    pub word: Bool<T>,
    pub unsigned: Bool<T>,
    // // TODO: we might need a selector for "MULSU" since no other instruction has "SU"
    pub JALR: T,
    pub JAL: T,
    pub AUIPC: T,
    // // Whether this instruction is reading from register A.
    pub reg_a_read: T,
}
/// An AIR table for memory accesses.
#[derive(AlignedBorrow, Default)]
#[repr(C)]
pub struct CpuCols<T> {
    /// The clock cycle value.
    pub clk: T,
    // /// The program counter value.
    pub pc: T,
    // /// The opcode for this cycle.
    pub opcode: T,
    // /// The first operand for this instruction.
    pub op_a: T,
    // /// The second operand for this instruction.
    pub op_b: T,
    // /// The third operand for this instruction.
    pub op_c: T,

    // Selectors for the opcode.
    pub selectors: OpcodeSelectors<T>,

    // // Operand values, either from registers or immediate values.
    pub op_a_val: Word<T>,
    pub op_b_val: Word<T>,
    pub op_c_val: Word<T>,

    // An addr that we are reading from or writing to.
    pub addr: Word<T>,
    // The associated memory value for `addr`.
    pub mem_val: Word<T>,

    // NOTE: This is actually a Bool<T>, but it might be easier to bus as a word for consistency with the register bus.
    pub branch_cond_val: Word<T>,
}

pub(crate) const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();
pub(crate) const CPU_COL_MAP: CpuCols<usize> = make_col_map();

const fn make_col_map() -> CpuCols<usize> {
    let indices_arr = indices_arr::<NUM_CPU_COLS>();
    unsafe { transmute::<[usize; NUM_CPU_COLS], CpuCols<usize>>(indices_arr) }
}

impl<AB: AirBuilder> AirConstraint<AB> for CpuCols<AB::Var> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &CpuCols<AB::Var> = main.row_slice(0).borrow();
        let next: &CpuCols<AB::Var> = main.row_slice(1).borrow();

        // Clock constraints
        builder.when_first_row().assert_zero(local.clk);
        builder
            .when_transition()
            .assert_eq(local.clk + AB::Expr::one(), next.clk);

        // TODO: lookup (pc, opcode, op_a, op_b, op_c, ... all selectors) in the program table with multiplicity 1

        //// Constraint op_a_val, op_b_val, op_c_val
        // TODO: lookup (clk, op_c, op_c_val, is_read=true) in the register table with multiplicity 1-imm_c
        // TODO: lookup (clk, op_b, op_b_val, is_read=true) in the register table with multiplicity 1-imm_b
        // Constraint the op_b_val and op_c_val columns when imm_b and imm_c are true.
        // TODO: modify these to be bit-decomposition constraints
        builder
            .when(local.selectors.imm_b)
            .assert_eq(reduce::<AB>(local.op_b_val), local.op_b);
        builder
            .when(local.selectors.imm_c)
            .assert_eq(reduce::<AB>(local.op_c_val), local.op_c);

        // We only read from the first register if there is a store or branch instruction. In all other cases we write.
<<<<<<< Updated upstream
        let reg_a_read =
            local.store_instruction + local.branch_instruction + local.multiply_instruction;
        // TODO: lookup (clk, op_a, op_a_val, is_read=reg_a_read) in the register table with multiplicity 1.
=======
        let reg_a_read = local.selectors.store_instruction
            + local.selectors.branch_instruction
            + local.selectors.multiply_instruction;
>>>>>>> Stashed changes

        //// For r-type, i-type and multiply instructions, we must constraint by an "opcode-oracle" table
        // TODO: lookup (clk, op_a_val, op_b_val, op_c_val) in the "opcode-oracle" table with multiplicity (register_instruction + immediate_instruction + multiply_instruction)

        //// For both load and store instructions, we must constraint mem_val to be a lookup of [addr]
        //// For load instructions
        // To constraint addr, we add op_b_val + op_c_val
        // TODO: lookup (clk, op_b_val, op_c_val, addr) in the "add" table with multiplicity load_instruction
        // To constraint mem_val, we lookup [addr] in the memory table
        // TODO: lookup (clk, addr, mem_val, is_read=true) in the memory table with multiplicity load_instruction
        // Now we must constraint mem_val and op_a_val
        // We bus this to a "match_word" table with a combination of s/u and h/b/w
        // TODO: lookup (clk, mem_val, op_a_val, byte, half, word, unsigned) in the "match_word" table with multiplicity load_instruction

        //// For store instructions
        // To constraint addr, we add op_a_val + op_c_val
        // TODO: lookup (clk, op_a_val, op_c_val, addr) in the "add" table with multiplicity store_instruction
        // To constraint mem_val, we lookup [addr] in the memory table
        // TODO: lookup (clk, addr, mem_val, is_read=false) in the memory table with multiplicity store_instruction
        // Now we must constraint mem_val and op_b_val
        // TODO: lookup (clk, mem_val, op_b_val, byte, half, word, unsigned) in the "match_word" table with multiplicity store_instruction

        //// For branch instructions
        /// TODO: lookup (clk, branch_cond_val, op_a_val, op_b_val) in the "branch" table with multiplicity branch_instruction
        // Increment the pc by 4 + op_c_val * branch_cond_val where we interpret the first result as a bool that it is.
        builder.when(local.selectors.branch_instruction).assert_eq(
            local.pc
                + AB::F::from_canonical_u8(4)
                + reduce::<AB>(local.op_c_val) * local.branch_cond_val.0[0],
            next.pc,
        );

        //// For jump instructions
        builder.when(local.selectors.jump_instruction).assert_eq(
            reduce::<AB>(local.op_a_val),
            local.pc + AB::F::from_canonical_u8(4),
        );
        builder.when(local.selectors.JAL).assert_eq(
            local.pc + AB::F::from_canonical_u8(4) + reduce::<AB>(local.op_b_val),
            next.pc,
        );
        builder
            .when(local.selectors.JALR)
            .assert_eq(reduce::<AB>(local.op_b_val) + local.op_c, next.pc);

        //// For system instructions

        //// Upper immediate instructions
        // lookup(clk, op_c_val, imm, 12) in SLT table with multiplicity AUIPC
        builder.when(local.selectors.AUIPC).assert_eq(
            reduce::<AB>(local.op_a_val),
            reduce::<AB>(local.op_c_val) + local.pc,
        );
    }
}
