use std::collections::HashMap;
pub mod cpu;
use cpu::CpuEvent;

pub mod alu;
use alu::AluEvent;

pub mod memory;
use memory::MemoryEvent;

pub mod segment;
use segment::Segment;

pub mod precompiles;

pub use valida_machine::Chip;
pub use valida_machine::ProgramROM;
use valida_machine::{InstructionWord, Operands, Word};
use valida_opcodes::AND32;
use valida_opcodes::SHL32;
pub use valida_opcodes::{ADD32, LOAD32, STOP, STORE32};

struct LookupEvent {}

struct Runtime {
    fp: u32,
    clk: u32,
    pc: u32,
    memory: HashMap<u32, Word<u8>>,
    inputs: Vec<u8>,
    outputs: Vec<u8>,
    program: ProgramROM<i32>,
    segment: Segment,
}

impl Runtime {
    fn new(program: &ProgramROM<i32>, input: &[u8]) -> Self {
        Self {
            fp: 2 << 16,
            clk: 0,
            pc: 0,
            memory: HashMap::new(),
            inputs: input.to_vec(),
            outputs: Vec::new(),
            program: program.clone(),
            segment: Segment {
                cpu_events: Vec::new(),
                memory_events: Vec::new(),
                alu_events: Vec::new(),
                // lookups: Vec::new(),
                program: program.clone(),
            },
        }
    }

    fn cpu_event(&mut self, instruction: &InstructionWord<i32>) {
        self.segment.cpu_events.push(CpuEvent {
            clk: self.clk,
            fp: self.fp,
            pc: self.pc,
            opcode: instruction.opcode,
            operands: instruction.operands,
        });
    }

    fn read_memory(&mut self, addr: u32) -> Word<u8> {
        let value = self
            .memory
            .get(&addr)
            .expect("Trying to read from uninitialized memory");
        self.segment.memory_events.push(MemoryEvent {
            clk: self.clk,
            addr,
            value: *value,
        });
        *value
    }

    fn write_memory(&mut self, addr: u32, value: Word<u8>) {
        // TODO: can you write to uninitialized memory?
        self.memory.insert(addr, value);
        self.segment.memory_events.push(MemoryEvent {
            clk: self.clk,
            addr,
            value,
        });
    }

    fn alu_op(&mut self, op: u32, b: Word<u8>, c: Word<u8>) -> Word<u8> {
        let result = match op {
            ADD32 => b + c,
            AND32 => b | c,
            SHL32 => b << c,
            _ => panic!("Invalid opcode"),
        };
        self.segment.alu_events.push(AluEvent {
            clk: self.clk,
            opcode: op,
            a: result,
            b,
            c,
        });
        result
    }

    fn run(&mut self) {
        // Iterate through the program, executing each instruction.
        let program_clone = self.program.clone();
        let current_instruction = program_clone.get_instruction(self.pc);
        let operands = current_instruction.operands;
        self.cpu_event(&current_instruction);

        let addr_a: u32 = (self.fp as i32 + operands.a()) as u32;
        let addr_b = (self.fp as i32 + operands.b()) as u32;
        let addr_c = (self.fp as i32 + operands.c()) as u32;

        match current_instruction.opcode {
            ADD32 | AND32 | SHL32 => {
                // Load values from addr_b and addr_c and store in addr_a
                let val_b = self.read_memory(addr_b);
                let val_c = self.read_memory(addr_c);
                let result = self.alu_op(current_instruction.opcode, val_b, val_c);
                self.write_memory(addr_a as u32, result);
                self.pc += 1;
            }
            LOAD32 => {
                // TODO: I think this might be a bit wrong based on other implementations.
                // Load the value from address fp+c into address fp+a.
                let val_c = self.read_memory(addr_c);
                self.write_memory(addr_a as u32, val_c);
                self.pc += 1;
            }
            STORE32 => todo!(),
            STOP => todo!(),
            _ => panic!("Invalid opcode"),
        }

        self.clk += 1;
    }
}
