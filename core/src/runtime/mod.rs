use crate::program::opcodes::*;
use crate::{
    alu::AluEvent,
    cpu::CpuEvent,
    program::{Instruction, ProgramROM},
    segment::Segment,
};
use anyhow::Result;

pub struct Runtime {
    fp: i32,
    clk: u32,
    pc: u32,
    memory: Vec<u8>,
    program: ProgramROM<i32>,
    segment: Segment,
}

impl Runtime {
    pub fn new(program: ProgramROM<i32>, memory_len: usize, stack_height: i32) -> Self {
        Self {
            fp: stack_height,
            clk: 0,
            pc: 0,
            memory: vec![0; memory_len],
            program: program.clone(),
            segment: Segment {
                cpu_events: Vec::new(),
                alu_events: Vec::new(),
                program,
            },
        }
    }

    fn cpu_event(&mut self, instruction: &Instruction<i32>) {
        self.segment.cpu_events.push(CpuEvent {
            clk: self.clk,
            fp: self.fp,
            pc: self.pc,
            instruction: *instruction,
        });
    }

    fn read_word(&mut self, addr: usize) -> i32 {
        i32::from_le_bytes(
            self.memory[addr as usize..addr as usize + 4]
                .try_into()
                .unwrap(),
        )
    }

    fn write_word(&mut self, addr: usize, value: i32) {
        // TODO: can you write to uninitialized memory?
        self.memory[addr as usize..addr as usize + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn alu_op(&mut self, op: Opcode, addr_d: usize, addr_1: usize, addr_2: usize) -> i32 {
        let v1 = self.read_word(addr_1);
        let v2 = self.read_word(addr_2);
        let result = match op {
            Opcode::ADD => v1 + v2,
            Opcode::AND => v1 | v2,
            Opcode::SLL => v1 << v2,
            _ => panic!("Invalid ALU opcode {}", op),
        };
        self.write_word(addr_d, result);
        self.segment.alu_events.push(AluEvent {
            clk: self.clk,
            opcode: op as u32,
            addr_d,
            addr_1,
            addr_2,
            v_d: result,
            v_1: v1,
            v_2: v2,
        });
        result
    }

    fn imm(&mut self, addr: usize, imm: i32) {
        self.write_word(addr, imm);
    }

    pub fn run(&mut self) -> Result<()> {
        // Iterate through the program, executing each instruction.
        let current_instruction = self.program.get_instruction(self.pc);
        let operands = current_instruction.operands.0;
        self.cpu_event(&current_instruction);

        match current_instruction.opcode {
            Opcode::ADD | Opcode::SUB | Opcode::XOR | Opcode::AND => {
                // Calculate address of each operand.
                let addr_d = self.fp + operands[0];
                let addr_1 = self.fp + operands[1];
                let addr_2 = self.fp + operands[2];

                self.alu_op(
                    current_instruction.opcode,
                    addr_d as usize,
                    addr_1 as usize,
                    addr_2 as usize,
                );
                self.pc += 1;
            }
            Opcode::IMM => {
                // Calculate address.
                let addr = (self.fp + operands[0]) as u32;
                let imm = operands[1];
                self.imm(addr as usize, imm);
            }
            _ => panic!("Invalid opcode {}", current_instruction.opcode),
        }

        self.clk += 1;
        Ok(())
    }
}
