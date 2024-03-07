use instruction::Instruction;
use opcode::Opcode;
use p3_field::PrimeField32;
use program::Program;

mod air;
mod instruction;
mod opcode;
mod program;

pub struct CpuEvent<F> {
    pub clk: F,
    pub pc: F,
    pub fp: F,
    pub instruction: Instruction<F>,
    pub opcode: Opcode,
    pub a: F,
    pub a_record: MemoryRecord,
    pub b: F,
    pub b_record: MemoryRecord,
    pub c: F,
    pub c_record: MemoryRecord,
}

pub struct MemoryRecord {
    pub value: u32,
    pub timestamp: u32,
    pub prev_value: u32,
    pub prev_timestamp: u32,
}

pub struct Runtime<F: PrimeField32 + Clone> {
    /// The frame pointer.
    pub fp: F,

    /// The program counter.
    pub pc: F,

    /// The program.
    pub program: Program<F>,

    /// Memory.
    pub memory: Vec<F>,
}

impl<F: PrimeField32 + Clone> Runtime<F> {
    /// Fetch the destination address and input operand values for an ALU instruction.
    fn alu_rr(&mut self, instruction: &Instruction<F>) -> (F, F, F) {
        if !instruction.imm_c {
            let a_ptr = self.fp + instruction.op_a;
            let b_val = self.memory[(self.fp + instruction.op_b).as_canonical_u32() as usize];
            let c_val = self.memory[(self.fp + instruction.op_c).as_canonical_u32() as usize];
            (a_ptr, b_val, c_val)
        } else {
            let a_ptr = self.fp + instruction.op_a;
            let b_val = self.memory[(self.fp + instruction.op_b).as_canonical_u32() as usize];
            let c_val = instruction.op_c;
            (a_ptr, b_val, c_val)
        }
    }

    /// Fetch the destination address input operand values for a load instruction (from heap).
    fn load_rr(&mut self, instruction: &Instruction<F>) -> (F, F) {
        if !instruction.imm_b {
            let a_ptr = self.fp + instruction.op_a;
            let b_ptr = self.memory[(self.fp + instruction.op_b).as_canonical_u32() as usize];
            let b = self.memory[(b_ptr).as_canonical_u32() as usize];
            (a_ptr, b)
        } else {
            let a_ptr = self.fp + instruction.op_a;
            (a_ptr, instruction.op_b)
        }
    }

    /// Fetch the destination address input operand values for a store instruction (from stack).
    fn store_rr(&mut self, instruction: &Instruction<F>) -> (F, F) {
        if !instruction.imm_b {
            let a_ptr = self.fp + instruction.op_a;
            let b = self.memory[(self.fp + instruction.op_b).as_canonical_u32() as usize];
            (a_ptr, b)
        } else {
            let a_ptr = self.fp + instruction.op_a;
            (a_ptr, instruction.op_b)
        }
    }

    /// Fetch the input operand values for a branch instruction.
    pub fn branch_rr(&mut self, instruction: &Instruction<F>) -> (F, F, F) {
        let a = self.memory[(self.fp + instruction.op_a).as_canonical_u32() as usize];
        let b = if !instruction.imm_b {
            self.memory[(self.fp + instruction.op_b).as_canonical_u32() as usize]
        } else {
            instruction.op_b
        };
        let c = instruction.op_c;
        (a, b, c)
    }

    pub fn run(&mut self) {
        while self.pc < F::from_canonical_u32(self.program.instructions.len() as u32) {
            let idx = self.pc.as_canonical_u32() as usize;
            let instruction = self.program.instructions[idx].clone();

            let mut next_pc = self.pc + F::one();
            match instruction.opcode {
                Opcode::ADD => {
                    let (a_ptr, b, c) = self.alu_rr(&instruction);
                    let a = b + c;
                    self.memory[(a_ptr).as_canonical_u32() as usize] = a;
                }
                Opcode::SUB => {
                    let (a_ptr, b, c) = self.alu_rr(&instruction);
                    let a = b - c;
                    self.memory[(a_ptr).as_canonical_u32() as usize] = a;
                }
                Opcode::MUL => {
                    let (a_ptr, b, c) = self.alu_rr(&instruction);
                    let a = b * c;
                    self.memory[(a_ptr).as_canonical_u32() as usize] = a;
                }
                Opcode::DIV => {
                    let (a_ptr, b, c) = self.alu_rr(&instruction);
                    let a = b / c;
                    self.memory[(a_ptr).as_canonical_u32() as usize] = a;
                }
                Opcode::LW => {
                    let (a_ptr, b) = self.load_rr(&instruction);
                    let a = b;
                    self.memory[(a_ptr).as_canonical_u32() as usize] = a;
                }
                Opcode::SW => {
                    let (a_ptr, b) = self.store_rr(&instruction);
                    let a = b;
                    self.memory[(a_ptr).as_canonical_u32() as usize] = a;
                }
                Opcode::BEQ => {
                    let (a, b, c) = self.branch_rr(&instruction);
                    if a == b {
                        next_pc = c;
                    }
                }
                Opcode::BNE => {
                    let (a, b, c) = self.branch_rr(&instruction);
                    if a != b {
                        next_pc = c;
                    }
                }
                Opcode::JAL => {
                    let imm = instruction.op_b;
                    let a_ptr = instruction.op_a + self.fp;
                    self.memory[(a_ptr).as_canonical_u32() as usize] = self.pc;
                    next_pc = self.pc + imm;
                }
                Opcode::JALR => {
                    let imm = instruction.op_c;
                    let b_ptr = instruction.op_b + self.fp;
                    let a_ptr = instruction.op_a + self.fp;

                    let b = self.memory[(b_ptr).as_canonical_u32() as usize];
                    let c = imm;
                    let a = self.pc + F::one();
                    self.memory[(a_ptr).as_canonical_u32() as usize] = a;
                    next_pc = b + c;
                }
            };

            self.pc = next_pc;
        }
    }
}

#[cfg(test)]
pub mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;

    use crate::{Instruction, Opcode, Program, Runtime};

    #[test]
    fn test_fibonacci() {
        // .main
        //  si 0(fp) 1 <-- a = 1
        //  si 1(fp) 1 <-- b = 1
        //  si 2(fp) 10 <-- iterations = 10
        // .body:
        //   add 3(fp) 0(fp) 1(fp) <-- tmp = a + b
        //   sw 0(fp) 1(fp) <-- a = b
        //   sw 1(fp) 3(fp) <-- b = tmp
        // . subi 2(fp) 2(fp) 1 <-- iterations -= 1
        //   bne 2(fp) 0 .body <-- if iterations != 0 goto .body
        let program = Program::<BabyBear> {
            instructions: vec![
                // .main
                Instruction::new(Opcode::SW, 0, 1, 0, true, true),
                Instruction::new(Opcode::SW, 1, 1, 0, true, true),
                Instruction::new(Opcode::SW, 2, 10, 0, true, true),
                // .body:
                Instruction::new(Opcode::ADD, 3, 0, 1, false, false),
                Instruction::new(Opcode::SW, 0, 1, 0, false, true),
                Instruction::new(Opcode::SW, 1, 3, 0, false, true),
                Instruction::new(Opcode::SUB, 2, 2, 1, false, true),
                Instruction::new(Opcode::BNE, 2, 0, 3, true, true),
            ],
        };
        let mut runtime = Runtime::<BabyBear> {
            program,
            fp: BabyBear::zero(),
            pc: BabyBear::zero(),
            memory: vec![BabyBear::zero(); 1024 * 1024],
        };
        runtime.run();
        assert_eq!(runtime.memory[1], BabyBear::from_canonical_u32(144));
    }

    #[test]
    fn test_add() {
        let program = Program::<BabyBear> {
            instructions: vec![
                Instruction {
                    opcode: Opcode::ADD,
                    op_a: BabyBear::from_canonical_u32(0),
                    op_b: BabyBear::from_canonical_u32(1),
                    op_c: BabyBear::from_canonical_u32(2),
                    imm_b: false,
                    imm_c: true,
                },
                Instruction {
                    opcode: Opcode::MUL,
                    op_a: BabyBear::from_canonical_u32(0),
                    op_b: BabyBear::from_canonical_u32(0),
                    op_c: BabyBear::from_canonical_u32(5),
                    imm_b: false,
                    imm_c: true,
                },
            ],
        };
        let mut runtime = Runtime::<BabyBear> {
            program,
            fp: BabyBear::zero(),
            pc: BabyBear::zero(),
            memory: vec![BabyBear::zero(); 1024 * 1024],
        };
        runtime.run();
        println!("{:?}", &runtime.memory[0..16]);
    }
}
