use crate::air::{reduce, AirConstraint, Word};
use crate::runtime::{Instruction, Opcode};
use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};
use p3_air::AirBuilder;
use p3_field::{AbstractField, PrimeField};
use p3_matrix::MatrixRowSlices;
use p3_util::indices_arr;
use valida_derive::AlignedBorrow;

use super::CpuEvent;

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
    pub byte: T,
    pub half: T,
    pub word: T,
    pub unsigned: T,
    // // TODO: we might need a selector for "MULSU" since no other instruction has "SU"
    pub JALR: T,
    pub JAL: T,
    pub AUIPC: T,
    // // Whether this instruction is reading from register A.
    pub reg_a_read: T,
}

impl<F: PrimeField> OpcodeSelectors<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        match instruction.opcode {
            // Register instructions
            Opcode::ADD
            | Opcode::SUB
            | Opcode::XOR
            | Opcode::OR
            | Opcode::AND
            | Opcode::SLL
            | Opcode::SRL
            | Opcode::SRA
            | Opcode::SLT
            | Opcode::SLTU => {
                // For register instructions, neither imm_b or imm_c should be turned on.
                self.register_instruction = F::one();
            }
            // Immediate instructions
            Opcode::ADDI
            | Opcode::XORI
            | Opcode::ORI
            | Opcode::ANDI
            | Opcode::SLLI
            | Opcode::SRLI
            | Opcode::SRAI
            | Opcode::SLTI
            | Opcode::SLTIU => {
                // For immediate instructions, imm_c should be turned on.
                self.imm_c = F::one();
                self.immediate_instruction = F::one();
            }
            // Load instructions
            Opcode::LB | Opcode::LH | Opcode::LW | Opcode::LBU | Opcode::LHU => {
                // For load instructions, imm_c should be turned on.
                self.imm_c = F::one();
                self.load_instruction = F::one();
                match instruction.opcode {
                    Opcode::LB | Opcode::LBU => {
                        self.byte = F::one();
                    }
                    Opcode::LH | Opcode::LHU => {
                        self.half = F::one();
                    }
                    Opcode::LW => {
                        self.word = F::one();
                    }
                    _ => {}
                }
            }
            // Store instructions
            Opcode::SB | Opcode::SH | Opcode::SW => {
                // For store instructions, imm_c should be turned on.
                self.imm_c = F::one();
                self.store_instruction = F::one();
                self.reg_a_read = F::one();
                match instruction.opcode {
                    Opcode::SB => {
                        self.byte = F::one();
                    }
                    Opcode::SH => {
                        self.half = F::one();
                    }
                    Opcode::SW => {
                        self.word = F::one();
                    }
                    _ => {}
                }
            }
            // Branch instructions
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                self.imm_c = F::one();
                self.branch_instruction = F::one();
                self.reg_a_read = F::one();
            }
            // Jump instructions
            Opcode::JAL => {
                self.JAL = F::one();
                self.imm_b = F::one();
                self.imm_c = F::one();
                self.jump_instruction = F::one();
            }
            Opcode::JALR => {
                self.JALR = F::one();
                self.imm_c = F::one();
                self.jump_instruction = F::one();
            }
            // Upper immediate instructions
            Opcode::LUI => {
                // Note that we convert a LUI opcode to a SLL opcode with both imm_b and imm_c turned on.
                // And the value of imm_c is 12.
                self.imm_b = F::one();
                self.imm_c = F::one();
                // In order to process lookups for the SLL opcode table, we'll also turn on the "immediate_instruction".
                self.immediate_instruction = F::one();
            }
            Opcode::AUIPC => {
                // Note that for an AUIPC opcode, we turn on both imm_b and imm_c.
                self.imm_b = F::one();
                self.imm_c = F::one();
                self.AUIPC = F::one();
                // We constraint that imm_c = imm_b << 12 by looking up SLL(op_c_val, op_b_val, 12) with multiplicity AUIPC.
                // Then we constraint op_a_val = op_c_val + pc by looking up ADD(op_a_val, op_c_val, pc) with multiplicity AUIPC.
            }
            // Multiply instructions
            Opcode::MUL
            | Opcode::MULH
            | Opcode::MULSU
            | Opcode::MULU
            | Opcode::DIV
            | Opcode::DIVU
            | Opcode::REM
            | Opcode::REMU => {
                self.multiply_instruction = F::one();
                match instruction.opcode {
                    // TODO: set byte/half/word/unsigned based on which variant of multiply.
                    _ => {}
                }
            }
            _ => panic!("Invalid opcode"),
        }
    }
}

#[derive(AlignedBorrow, Default)]
#[repr(C)]
pub struct InstructionCols<T> {
    // /// The opcode for this cycle.
    pub opcode: T,
    // /// The first operand for this instruction.
    pub op_a: T,
    // /// The second operand for this instruction.
    pub op_b: T,
    // /// The third operand for this instruction.
    pub op_c: T,
}

impl<F: PrimeField> InstructionCols<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        self.opcode = F::from_canonical_u32(instruction.opcode as u32);
        match instruction.opcode {
            Opcode::LUI => {
                // For LUI, we convert it to a SLL instruction with imm_b and imm_c turned on.
                self.opcode = F::from_canonical_u32(Opcode::SLL as u32);
                assert_eq!(instruction.op_c as u32, 12);
            }
            Opcode::AUIPC => {
                // For AUIPC, we set the 3rd operand to imm_b << 12.
                assert_eq!(instruction.op_c as u32, instruction.op_b << 12);
            }
            _ => {}
        }
        self.op_a = F::from_canonical_u32(instruction.op_a as u32);
        self.op_b = F::from_canonical_u32(instruction.op_b as u32);
        self.op_c = F::from_canonical_u32(instruction.op_c as u32);
    }
}

/// An AIR table for memory accesses.
#[derive(AlignedBorrow, Default)]
#[repr(C)]
pub struct CpuCols<T> {
    /// The clock cycle value.
    pub clk: T,
    // /// The program counter value.
    pub pc: T,

    // Columns related to the instruction.
    pub instruction: InstructionCols<T>,
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
        // Constraint the op_b_val and op_c_val columns when imm_b and imm_c are true.
        builder
            .when(local.selectors.imm_b)
            .assert_eq(reduce::<AB>(local.op_b_val), local.instruction.op_b);
        builder
            .when(local.selectors.imm_c)
            .assert_eq(reduce::<AB>(local.op_c_val), local.instruction.op_c);

        // We only read from the first register if there is a store or branch instruction. In all other cases we write.
        let reg_a_read = local.selectors.store_instruction
            + local.selectors.branch_instruction
            + local.selectors.multiply_instruction;

        //// For r-type, i-type and multiply instructions, we must constraint by an "opcode-oracle" table
        // TODO: lookup (clk, op_a_val, op_b_val, op_c_val) in the "opcode-oracle" table with multiplicity (register_instruction + immediate_instruction + multiply_instruction)

        //// For branch instructions
        // TODO: lookup (clk, branch_cond_val, op_a_val, op_b_val) in the "branch" table with multiplicity branch_instruction
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
        builder.when(local.selectors.JALR).assert_eq(
            reduce::<AB>(local.op_b_val) + local.instruction.op_c,
            next.pc,
        );

        //// For system instructions

        //// Upper immediate instructions
        // lookup(clk, op_c_val, imm, 12) in SLT table with multiplicity AUIPC
        builder.when(local.selectors.AUIPC).assert_eq(
            reduce::<AB>(local.op_a_val),
            reduce::<AB>(local.op_c_val) + local.pc,
        );
    }
}
