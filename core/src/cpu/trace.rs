use super::air::{CpuCols, InstructionCols, OpcodeSelectors, CPU_COL_MAP, NUM_CPU_COLS};
use super::CpuEvent;
use crate::lookup::{Interaction, IsRead};
use core::mem::{size_of, transmute};
use p3_air::{AirBuilder, BaseAir, VirtualPairCol};

use crate::air::Word;
use crate::runtime::chip::Chip;
use crate::runtime::{Instruction, Opcode, Runtime};
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

pub struct CpuChip<F: PrimeField> {
    pub _phantom: core::marker::PhantomData<F>,
}

impl<F: PrimeField> Chip<F> for CpuChip<F> {
    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F> {
        let mut rows = runtime
            .cpu_events
            .iter() // TODO make this a par_iter
            .enumerate()
            .map(|(n, op)| self.event_to_row(*op))
            .collect::<Vec<_>>();

        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_CPU_COLS);

        // TODO: pad to a power of 2.
        // Self::pad_to_power_of_two(&mut trace.values);

        trace
    }

    fn sends(&self) -> Vec<Interaction<F>> {
        let mut interactions = Vec::new();

        // lookup (clk, op_a, op_a_val, is_read=1-branch_op) in the register table with multiplicity 1.
        // We always write to the first register, unless we are doing a branch operation in which case we read from it.
        interactions.push(Interaction::lookup_register(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.instruction.op_a,
            CPU_COL_MAP.op_a_val,
            IsRead::Expr(VirtualPairCol::new_main(
                vec![(CPU_COL_MAP.selectors.branch_op, F::neg_one())],
                F::one(),
            )),
            VirtualPairCol::constant(F::one()),
        ));
        // lookup (clk, op_c, op_c_val, is_read=true) in the register table with multiplicity 1-imm_c
        // lookup (clk, op_b, op_b_val, is_read=true) in the register table with multiplicity 1-imm_b
        interactions.push(Interaction::lookup_register(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.instruction.op_c,
            CPU_COL_MAP.op_c_val,
            IsRead::Bool(true),
            VirtualPairCol::new_main(vec![(CPU_COL_MAP.selectors.imm_c, F::neg_one())], F::one()), // 1-imm_c
        ));
        interactions.push(Interaction::lookup_register(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.instruction.op_b,
            CPU_COL_MAP.op_b_val,
            IsRead::Bool(true),
            VirtualPairCol::new_main(vec![(CPU_COL_MAP.selectors.imm_b, F::neg_one())], F::one()), // 1-imm_b
        ));

        // TODO: add interactions with all tables, with selectors `add_op, sub_op, mul_op, etc.`
        interactions.push(Interaction::add(
            CPU_COL_MAP.op_a_val,
            CPU_COL_MAP.op_b_val,
            CPU_COL_MAP.op_c_val,
            VirtualPairCol::single_main(CPU_COL_MAP.selectors.add_op),
        ));

        //// For both load and store instructions, we must constraint that the addr = op_b_val + op_c_val
        // lookup (clk, op_b_val, op_c_val, addr) in the "add" table with multiplicity load_instruction
        interactions.push(Interaction::add(
            CPU_COL_MAP.addr,
            CPU_COL_MAP.op_b_val,
            CPU_COL_MAP.op_c_val,
            VirtualPairCol::single_main(CPU_COL_MAP.selectors.mem_op),
        ));
        // To constraint mem_val, we lookup [addr] in the memory table
        // is_read is set to the `mem_read` flag, which = 1 for load instructions and 0 for store instructions.
        interactions.push(Interaction::lookup_memory(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.addr,
            CPU_COL_MAP.mem_val,
            IsRead::Expr(VirtualPairCol::single_main(CPU_COL_MAP.selectors.mem_read)),
            VirtualPairCol::single_main(CPU_COL_MAP.selectors.mem_op),
        ));
        // Now we must constraint mem_val and op_a_val
        // We bus this to a "match_word" table with a combination of s/u and h/b/w
        // TODO: lookup (clk, opcode, mem_val, op_a_val) in the "match_word" table with multiplicity load_instruction
        interactions
    }

    fn receives(&self) -> Vec<Interaction<F>> {
        // The CPU table does not receive from anybody.
        vec![]
    }
}

impl<F: PrimeField> CpuChip<F> {
    fn event_to_row(&self, event: CpuEvent) -> [F; NUM_CPU_COLS] {
        let mut row = [F::zero(); NUM_CPU_COLS];
        let cols: &mut CpuCols<F> = unsafe { transmute(&mut row) };
        cols.clk = F::from_canonical_u32(event.clk);
        cols.pc = F::from_canonical_u32(event.pc);

        self.populate_instruction(&mut cols.instruction, event.instruction);
        self.populate_selectors(&mut cols.selectors, event.instruction.opcode);

        cols.op_a_val = event.operands[0].into();
        cols.op_b_val = event.operands[1].into();
        cols.op_c_val = event.operands[2].into();

        self.populate_memory(cols, event);
        self.populate_branch(cols, event);
        row
    }

    fn populate_instruction(&self, cols: &mut InstructionCols<F>, instruction: Instruction) {
        cols.opcode = F::from_canonical_u32(instruction.opcode as u32);
        match instruction.opcode {
            Opcode::LUI => {
                // For LUI, we convert it to a SLL instruction with imm_b and imm_c turned on.
                cols.opcode = F::from_canonical_u32(Opcode::SLL as u32);
                assert_eq!(instruction.c as u32, 12);
            }
            Opcode::AUIPC => {
                // For AUIPC, we set the 3rd operand to imm_b << 12.
                assert_eq!(instruction.c as u32, instruction.b << 12);
            }
            _ => {}
        }
        cols.op_a = F::from_canonical_u32(instruction.a as u32);
        cols.op_b = F::from_canonical_u32(instruction.b as u32);
        cols.op_c = F::from_canonical_u32(instruction.c as u32);
    }

    fn populate_selectors(&self, cols: &mut OpcodeSelectors<F>, opcode: Opcode) {
        match opcode {
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
                match opcode {
                    Opcode::ADD => {
                        cols.add_op = F::one();
                    }
                    Opcode::SUB => {
                        cols.sub_op = F::one();
                    }
                    Opcode::XOR | Opcode::OR | Opcode::AND => {
                        cols.bitwise_op = F::one();
                    }
                    Opcode::SLL | Opcode::SRL => {
                        cols.shift_op = F::one();
                    }
                    Opcode::SLT | Opcode::SLTU => {
                        cols.lt_op = F::one();
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
                cols.imm_c = F::one();
                match opcode {
                    Opcode::ADDI => {
                        cols.add_op = F::one();
                    }
                    Opcode::XORI | Opcode::ORI | Opcode::ANDI => {
                        cols.bitwise_op = F::one();
                    }
                    Opcode::SLLI | Opcode::SRLI => {
                        cols.shift_op = F::one();
                    }
                    Opcode::SLTI | Opcode::SLTIU => {
                        cols.lt_op = F::one();
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
                cols.imm_c = F::one();
                cols.mem_op = F::one();
                cols.mem_read = F::one();
            }
            // Store instructions
            Opcode::SB | Opcode::SH | Opcode::SW => {
                // For store instructions, imm_c should be turned on, but mem_read stays off.
                cols.imm_c = F::one();
                cols.mem_op = F::one();
            }
            // Branch instructions
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                cols.imm_c = F::one();
                cols.branch_op = F::one();
            }
            // Jump instructions
            Opcode::JAL => {
                cols.jal = F::one();
                cols.imm_b = F::one();
                cols.imm_c = F::one();
            }
            Opcode::JALR => {
                cols.jalr = F::one();
                cols.imm_c = F::one();
            }
            // Upper immediate instructions
            Opcode::LUI => {
                // Note that we convert a LUI opcode to a SLL opcode with both imm_b and imm_c turned on.
                // And the value of imm_c is 12.
                cols.imm_b = F::one();
                cols.imm_c = F::one();
                // In order to process lookups for the SLL opcode table, we'll also turn on the "shift_op".
                cols.shift_op = F::one();
            }
            Opcode::AUIPC => {
                // Note that for an AUIPC opcode, we turn on both imm_b and imm_c.
                cols.imm_b = F::one();
                cols.imm_c = F::one();
                cols.auipc = F::one();
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
                cols.mul_op = F::one();
            }
            _ => panic!("Invalid opcode"),
        }
    }

    fn populate_memory(&self, cols: &mut CpuCols<F>, event: CpuEvent) {
        if let Some(memory_value) = event.memory_value {
            cols.mem_val = memory_value.into();
        }
        if let Some(addr) = event.addr {
            cols.addr = addr.into();
        }
    }

    fn populate_branch(&self, cols: &mut CpuCols<F>, event: CpuEvent) {
        if let Some(branch_condition) = event.branch_condition {
            cols.branch_cond_val = (branch_condition as u32).into();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::runtime::tests::get_simple_program;
    use crate::runtime::Instruction;
    use p3_baby_bear::BabyBear;

    use super::*;
    #[test]
    fn generate_trace() {
        let program = vec![];
        let mut runtime = Runtime::new(program);
        let events = vec![CpuEvent {
            clk: 6,
            pc: 1,
            instruction: Instruction {
                opcode: Opcode::ADD,
                a: 0,
                b: 1,
                c: 2,
            },
            operands: [1, 2, 3],
            addr: None,
            memory_value: None,
            branch_condition: None,
        }];
        let chip = CpuChip::<BabyBear> {
            _phantom: Default::default(),
        };
        runtime.cpu_events = events;
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        println!("{:?}", trace.values)
    }

    #[test]
    fn generate_trace_simple_program() {
        let program = get_simple_program();
        let mut runtime = Runtime::new(program);
        runtime.run();
        let chip = CpuChip::<BabyBear> {
            _phantom: Default::default(),
        };
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        println!("{:?}", trace.values)
    }
}
