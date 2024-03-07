use p3_field::PrimeField32;

#[derive(Debug, Clone)]
pub enum Opcode {
    // Arithmetic instructions.
    ADD = 0,
    SUB = 1,
    MUL = 2,
    DIV = 3,

    // Memory instructions.
    LW = 4,
    SW = 5,

    // Branch instructions.
    BEQ = 6,
    BNE = 7,

    // Jump instructions.
    JAL = 8,
    JALR = 9,
}

#[derive(Debug, Clone)]
pub struct Instruction<F: PrimeField32 + Clone> {
    /// Which operation to execute.
    pub opcode: Opcode,

    /// The first operand.
    pub op_a: F,

    /// The second operand.
    pub op_b: F,

    /// The third operand.
    pub op_c: F,

    /// Whether the second operand is an immediate value.
    pub imm_b: bool,

    /// Whether the third operand is an immediate value.
    pub imm_c: bool,
}

#[derive(Debug, Clone)]
pub struct Program<F: PrimeField32 + Clone> {
    /// The instructions of the program.
    pub instructions: Vec<Instruction<F>>,

    /// The start address of the program.
    pub pc_start: F,

    /// The base address of the program.
    pub pc_base: F,
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
        let b = self.memory[(self.fp + instruction.op_b).as_canonical_u32() as usize];
        let c = instruction.op_c;
        (a, b, c)
    }

    pub fn run(&mut self) {
        while self.pc - self.program.pc_base
            < F::from_canonical_u32(self.program.instructions.len() as u32)
        {
            let idx = (self.pc - self.program.pc_base).as_canonical_u32() as usize;
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
            pc_start: BabyBear::from_canonical_u32(0),
            pc_base: BabyBear::from_canonical_u32(0),
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
