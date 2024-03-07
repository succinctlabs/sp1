use std::collections::HashMap;

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
    pub opcode: Opcode,
    pub op_a: F,
    pub op_b: F,
    pub op_c: F,
    pub imm_b: bool,
    pub imm_c: bool,
}

#[derive(Debug, Clone)]
pub struct Program<F: PrimeField32 + Clone> {
    pub instructions: Vec<Instruction<F>>,
    pub pc_start: F,
    pub pc_base: F,
}

pub struct Runtime<F: PrimeField32 + Clone> {
    pub fp: F,
    pub pc: F,
    pub program: Program<F>,
    pub memory: HashMap<F, F>,
}

impl<F: PrimeField32 + Clone> Runtime<F> {
    pub fn execute(&mut self, instruction: &Instruction<F>) {
        todo!()
    }

    fn alu_rr(&mut self, instruction: &Instruction<F>) -> (F, F) {
        let zero = F::zero();
        if !instruction.imm_c {
            let c = self
                .memory
                .get(&(self.fp + instruction.op_c))
                .unwrap_or(&zero);
            let b = self
                .memory
                .get(&(self.fp + instruction.op_b))
                .unwrap_or(&zero);
            (*b, *c)
        } else if !instruction.imm_b && instruction.imm_c {
            let c = instruction.op_c;
            let b = self
                .memory
                .get(&(self.fp + instruction.op_b))
                .unwrap_or(&zero);
            (*b, c)
        } else {
            unreachable!()
        }
    }

    fn load_rr(&mut self, instruction: &Instruction<F>) -> F {
        let zero = F::zero();
        if !instruction.imm_b {
            let b_addr = self
                .memory
                .get(&(self.fp + instruction.op_b))
                .unwrap_or(&zero);
            let b = self.memory.get(b_addr).unwrap_or(&zero);
            *b
        } else {
            instruction.op_b
        }
    }

    fn store_rr(&mut self, instruction: &Instruction<F>) -> (F, F) {
        let zero = F::zero();
        if !instruction.imm_b {
            let b = self
                .memory
                .get(&(self.fp + instruction.op_b))
                .unwrap_or(&zero);
            let a_addr = self
                .memory
                .get(&(self.fp + instruction.op_a))
                .unwrap_or(&zero);
            (*a_addr, *b)
        } else {
            let a_addr = self
                .memory
                .get(&(self.fp + instruction.op_a))
                .unwrap_or(&zero);
            (*a_addr, instruction.op_b)
        }
    }

    pub fn branch_rr(&mut self, instruction: &Instruction<F>) -> (F, F, F) {
        let zero = F::zero();
        let c = instruction.op_c;
        let b = self
            .memory
            .get(&(self.fp + instruction.op_b))
            .unwrap_or(&zero);
        let a = self
            .memory
            .get(&(self.fp + instruction.op_a))
            .unwrap_or(&zero);
        (*a, *b, c)
    }

    pub fn run(&mut self) {
        while self.pc - self.program.pc_base
            < F::from_canonical_u32(self.program.instructions.len() as u32)
        {
            let idx = (self.pc - self.program.pc_base).as_canonical_u32() as usize;
            let instruction = self.program.instructions[idx].clone();

            match instruction.opcode {
                Opcode::ADD => {
                    let (b, c) = self.alu_rr(&instruction);
                    let a = b + c;
                    self.memory.insert(self.fp + instruction.op_a, a);
                }
                Opcode::SUB => {
                    let (b, c) = self.alu_rr(&instruction);
                    let a = b - c;
                    self.memory.insert(self.fp + instruction.op_a, a);
                }
                Opcode::MUL => {
                    let (b, c) = self.alu_rr(&instruction);
                    let a = b * c;
                    self.memory.insert(self.fp + instruction.op_a, a);
                }
                Opcode::DIV => {
                    let (b, c) = self.alu_rr(&instruction);
                    let a = b / c;
                    self.memory.insert(self.fp + instruction.op_a, a);
                }
                Opcode::LW => {
                    let b = self.load_rr(&instruction);
                    let a = b;
                    self.memory.insert(self.fp + instruction.op_a, a);
                }
                Opcode::SW => {
                    let (a_addr, b) = self.store_rr(&instruction);
                    let a = b;
                    self.memory.insert(a_addr, a);
                }
                Opcode::BEQ => {
                    let (a, b, c) = self.branch_rr(&instruction);
                    if a == b {
                        self.pc = c;
                    }
                }
                Opcode::BNE => {
                    let (a, b, c) = self.branch_rr(&instruction);
                    if a != b {
                        self.pc = c;
                    }
                }
                Opcode::JAL => {
                    let imm = instruction.op_c;
                    let b_addr = instruction.op_b + self.fp;
                    self.memory.insert(b_addr, self.pc);
                    self.pc += self.pc + imm;
                }
                Opcode::JALR => {
                    let imm = instruction.op_c;
                    let b = self.memory.get(&(self.fp + instruction.op_b)).unwrap();
                    let b_addr = *b;
                    self.memory.insert(b_addr, self.pc);
                    self.pc = b_addr + imm;
                }
            };

            todo!()
        }
    }
}
