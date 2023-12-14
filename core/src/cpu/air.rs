use crate::air::Word;
use crate::runtime::{Instruction, Opcode};
use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};
use p3_air::Air;
use p3_air::AirBuilder;
use p3_air::BaseAir;
use p3_field::{AbstractField, PrimeField};
use p3_matrix::MatrixRowSlices;
use p3_util::indices_arr;
use valida_derive::AlignedBorrow;

use super::trace::CpuChip;

#[derive(AlignedBorrow, Default)]
#[repr(C)]
pub struct OpcodeSelectors<T> {
    // // Whether op_b is an immediate value.
    pub imm_b: T,
    // Whether op_c is an immediate value.
    pub imm_c: T,

    // Table selectors for opcodes.
    pub add_op: T,
    pub sub_op: T,
    pub mul_op: T,
    pub div_op: T,
    pub shift_op: T,
    pub bitwise_op: T,
    pub lt_op: T,

    // Memory operation
    pub mem_op: T,
    pub mem_read: T,

    // Specific instruction selectors.
    pub jalr: T,
    pub jal: T,
    pub auipc: T,

    // Whether this is a branch op.
    pub branch_op: T,

    // Whether this is a no-op.
    pub noop: T,
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
                match instruction.opcode {
                    Opcode::ADD => {
                        self.add_op = F::one();
                    }
                    Opcode::SUB => {
                        self.sub_op = F::one();
                    }
                    Opcode::XOR | Opcode::OR | Opcode::AND => {
                        self.bitwise_op = F::one();
                    }
                    Opcode::SLL | Opcode::SRL => {
                        self.shift_op = F::one();
                    }
                    Opcode::SLT | Opcode::SLTU => {
                        self.lt_op = F::one();
                    }
                    Opcode::SRA => {
                        panic!("SRA not implemented");
                    }
                    _ => {
                        panic!("unexpected opcode in register instruction table processing.")
                    }
                }
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
                match instruction.opcode {
                    Opcode::ADDI => {
                        self.add_op = F::one();
                    }
                    Opcode::XORI | Opcode::ORI | Opcode::ANDI => {
                        self.bitwise_op = F::one();
                    }
                    Opcode::SLLI | Opcode::SRLI => {
                        self.shift_op = F::one();
                    }
                    Opcode::SLTI | Opcode::SLTIU => {
                        self.lt_op = F::one();
                    }
                    Opcode::SRAI => {
                        panic!("SRAI not implemented");
                    }
                    _ => {
                        panic!("unexpected opcode in immediate instruction table processing.")
                    }
                }
            }
            // Load instructions
            Opcode::LB | Opcode::LH | Opcode::LW | Opcode::LBU | Opcode::LHU => {
                // For load instructions, imm_c should be turned on.
                self.imm_c = F::one();
                self.mem_op = F::one();
                self.mem_read = F::one();
            }
            // Store instructions
            Opcode::SB | Opcode::SH | Opcode::SW => {
                // For store instructions, imm_c should be turned on, but mem_read stays off.
                self.imm_c = F::one();
                self.mem_op = F::one();
            }
            // Branch instructions
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                self.imm_c = F::one();
                self.branch_op = F::one();
            }
            // Jump instructions
            Opcode::JAL => {
                self.jal = F::one();
                self.imm_b = F::one();
                self.imm_c = F::one();
            }
            Opcode::JALR => {
                self.jalr = F::one();
                self.imm_c = F::one();
            }
            // Upper immediate instructions
            Opcode::LUI => {
                // Note that we convert a LUI opcode to a SLL opcode with both imm_b and imm_c turned on.
                // And the value of imm_c is 12.
                self.imm_b = F::one();
                self.imm_c = F::one();
                // In order to process lookups for the SLL opcode table, we'll also turn on the "shift_op".
                self.shift_op = F::one();
            }
            Opcode::AUIPC => {
                // Note that for an AUIPC opcode, we turn on both imm_b and imm_c.
                self.imm_b = F::one();
                self.imm_c = F::one();
                self.auipc = F::one();
                // We constraint that imm_c = imm_b << 12 by looking up SLL(op_c_val, op_b_val, 12) with multiplicity AUIPC.
                // Then we constraint op_a_val = op_c_val + pc by looking up ADD(op_a_val, op_c_val, pc) with multiplicity AUIPC.
            }
            // Multiply instructions
            Opcode::MUL
            | Opcode::MULH
            | Opcode::MULHSU
            | Opcode::MULHU
            | Opcode::DIV
            | Opcode::DIVU
            | Opcode::REM
            | Opcode::REMU => {
                self.mul_op = F::one();
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
    pub op_a: Word<T>,
    // /// The second operand for this instruction.
    pub op_b: Word<T>,
    // /// The third operand for this instruction.
    pub op_c: Word<T>,
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
        self.op_a = instruction.op_a.into();
        self.op_b = instruction.op_b.into();
        self.op_c = instruction.op_c.into();
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

impl<F> BaseAir<F> for CpuChip {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}

impl<AB> Air<AB> for CpuChip
where
    AB: AirBuilder,
{
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
        for i in 0..4 {
            builder
                .when(local.selectors.imm_b)
                .assert_eq(local.op_b_val[i], local.instruction.op_b[i]);
            builder
                .when(local.selectors.imm_c)
                .assert_eq(local.op_c_val[i], local.instruction.op_c[i]);
        }

        builder.assert_eq(
            local.pc * local.pc * local.pc,
            local.pc * local.pc * local.pc,
        );

        //// For r-type, i-type and multiply instructions, we must constraint by an "opcode-oracle" table
        // TODO: lookup (clk, op_a_val, op_b_val, op_c_val) in the "opcode-oracle" table with multiplicity (register_instruction + immediate_instruction + multiply_instruction)

        //// For branch instructions
        // TODO: lookup (clk, branch_cond_val, op_a_val, op_b_val) in the "branch" table with multiplicity branch_instruction
        // Increment the pc by 4 + op_c_val * branch_cond_val where we interpret the first result as a bool that it is.

        // builder.when(local.selectors.branch_op).assert_eq(
        //     local.pc
        //         + AB::F::from_canonical_u8(4)
        //         + reduce::<AB>(local.op_c_val) * local.branch_cond_val.0[0],
        //     next.pc,
        // );

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
    }
}
