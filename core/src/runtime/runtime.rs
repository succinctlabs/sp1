use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
};

use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    alu::{add::AddChip, bitwise::BitwiseChip, sub::SubChip, AluEvent},
    cpu::{trace::CpuChip, CpuEvent},
    memory::{MemOp, MemoryEvent},
    program::ProgramChip,
    utils::Chip,
};

use super::{instruction::Instruction, opcode::Opcode};

/// A register stores a 32-bit value used by operations.
#[derive(Debug, Clone, Copy)]
pub enum Register {
    X0 = 0,
    X1 = 1,
    X2 = 2,
    X3 = 3,
    X4 = 4,
    X5 = 5,
    X6 = 6,
    X7 = 7,
    X8 = 8,
    X9 = 9,
    X10 = 10,
    X11 = 11,
    X12 = 12,
    X13 = 13,
    X14 = 14,
    X15 = 15,
    X16 = 16,
    X17 = 17,
    X18 = 18,
    X19 = 19,
    X20 = 20,
    X21 = 21,
    X22 = 22,
    X23 = 23,
    X24 = 24,
    X25 = 25,
    X26 = 26,
    X27 = 27,
    X28 = 28,
    X29 = 29,
    X30 = 30,
    X31 = 31,
}

impl Register {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Register::X0,
            1 => Register::X1,
            2 => Register::X2,
            3 => Register::X3,
            4 => Register::X4,
            5 => Register::X5,
            6 => Register::X6,
            7 => Register::X7,
            8 => Register::X8,
            9 => Register::X9,
            10 => Register::X10,
            11 => Register::X11,
            12 => Register::X12,
            13 => Register::X13,
            14 => Register::X14,
            15 => Register::X15,
            16 => Register::X16,
            17 => Register::X17,
            18 => Register::X18,
            19 => Register::X19,
            20 => Register::X20,
            21 => Register::X21,
            22 => Register::X22,
            23 => Register::X23,
            24 => Register::X24,
            25 => Register::X25,
            26 => Register::X26,
            27 => Register::X27,
            28 => Register::X28,
            29 => Register::X29,
            30 => Register::X30,
            31 => Register::X31,
            _ => panic!("Invalid register"),
        }
    }
}

impl Display for Register {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Register::X0 => write!(f, "%x0"),
            Register::X1 => write!(f, "%x1"),
            Register::X2 => write!(f, "%x2"),
            Register::X3 => write!(f, "%x3"),
            Register::X4 => write!(f, "%x4"),
            Register::X5 => write!(f, "%x5"),
            Register::X6 => write!(f, "%x6"),
            Register::X7 => write!(f, "%x7"),
            Register::X8 => write!(f, "%x8"),
            Register::X9 => write!(f, "%x9"),
            Register::X10 => write!(f, "%x10"),
            Register::X11 => write!(f, "%x11"),
            Register::X12 => write!(f, "%x12"),
            Register::X13 => write!(f, "%x13"),
            Register::X14 => write!(f, "%x14"),
            Register::X15 => write!(f, "%x15"),
            Register::X16 => write!(f, "%x16"),
            Register::X17 => write!(f, "%x17"),
            Register::X18 => write!(f, "%x18"),
            Register::X19 => write!(f, "%x19"),
            Register::X20 => write!(f, "%x20"),
            Register::X21 => write!(f, "%x21"),
            Register::X22 => write!(f, "%x22"),
            Register::X23 => write!(f, "%x23"),
            Register::X24 => write!(f, "%x24"),
            Register::X25 => write!(f, "%x25"),
            Register::X26 => write!(f, "%x26"),
            Register::X27 => write!(f, "%x27"),
            Register::X28 => write!(f, "%x28"),
            Register::X29 => write!(f, "%x29"),
            Register::X30 => write!(f, "%x30"),
            Register::X31 => write!(f, "%x31"),
        }
    }
}

// An implementation of a runtime for the Curta VM.
//
// The runtime is responsible for executing a user program and tracing important events which occur
// during execution (i.e., memory reads, alu operations, etc).
//
// For more information on the RV32IM instruction set, see the following:
// https://www.cs.sfu.ca/~ashriram/Courses/CS295/assets/notebooks/RISCV/RISCV_CARD.pdf
pub struct Runtime {
    /// The clock keeps track of how many instructions have been executed.
    pub clk: u32,

    /// The program counter keeps track of the next instruction.
    pub pc: u32,

    /// The prgram used during execution.
    pub program: Vec<Instruction>,

    /// The memory which instructions operate over.
    pub memory: BTreeMap<u32, u32>,

    /// A trace of the CPU events which get emitted during execution.
    pub cpu_events: Vec<CpuEvent>,

    /// A trace of the memory events which get emitted during execution.
    pub memory_events: Vec<MemoryEvent>,

    /// A trace of the ADD, and ADDI events.
    pub add_events: Vec<AluEvent>,

    /// A trace of the SUB events.
    pub sub_events: Vec<AluEvent>,

    /// A trace of the XOR, XORI, OR, ORI, AND, and ANDI events.
    pub bitwise_events: Vec<AluEvent>,
}

impl Runtime {
    /// Create a new runtime.
    pub fn new(program: Vec<Instruction>) -> Self {
        Self {
            clk: 0,
            pc: 0,
            memory: BTreeMap::new(),
            program,
            cpu_events: Vec::new(),
            memory_events: Vec::new(),
            add_events: Vec::new(),
            sub_events: Vec::new(),
            bitwise_events: Vec::new(),
        }
    }

    pub fn new_with_pc(program: Vec<Instruction>, init_pc: u32) -> Self {
        Self {
            clk: 0,
            pc: init_pc,
            memory: BTreeMap::new(),
            program,
            cpu_events: Vec::new(),
            memory_events: Vec::new(),
            add_events: Vec::new(),
            sub_events: Vec::new(),
            bitwise_events: Vec::new(),
        }
    }

    /// Read from memory.
    fn mr(&mut self, addr: u32) -> u32 {
        let value = match self.memory.get(&addr) {
            Some(value) => *value,
            None => 0,
        };
        self.emit_memory(self.clk, addr, MemOp::Read, value);
        return value;
    }

    /// Write to memory.
    fn mw(&mut self, addr: u32, value: u32) {
        self.memory.insert(addr, value);
        self.emit_memory(self.clk, addr, MemOp::Write, value);
    }

    /// Convert a register to a memory address.
    fn r2m(&self, register: Register) -> u32 {
        1024 * 1024 * 8 + (register as u32)
    }

    /// Read from register.
    fn rr(&mut self, register: Register) -> u32 {
        let addr = self.r2m(register);
        self.mr(addr)
    }

    /// Write to register.
    fn rw(&mut self, register: Register, value: u32) {
        let addr = self.r2m(register);
        self.mw(addr, value);
    }

    /// Get the current values of the registers.
    pub fn registers(&self) -> [u32; 32] {
        let mut registers = [0; 32];
        for i in 0..32 {
            let addr = self.r2m(Register::from_u32(i as u32));
            registers[i] = match self.memory.get(&addr) {
                Some(value) => *value,
                None => 0,
            };
        }
        return registers;
    }

    /// Fetch the instruction at the current program counter.
    fn fetch(&self) -> Instruction {
        let idx = (self.pc / 4) as usize;
        return self.program[idx];
    }

    /// Emit a CPU event.
    fn emit_cpu(
        &mut self,
        clk: u32,
        pc: u32,
        instruction: Instruction,
        a: u32,
        b: u32,
        c: u32,
        memory_value: Option<u32>,
    ) {
        self.cpu_events.push(CpuEvent {
            clk: clk,
            pc: pc,
            instruction,
            a,
            b,
            c,
            memory_value,
        });
    }

    /// Emit a memory event.
    fn emit_memory(&mut self, clk: u32, addr: u32, op: MemOp, value: u32) {
        self.memory_events.push(MemoryEvent {
            clk,
            addr,
            op,
            value,
        });
    }

    /// Emit an ALU event.
    fn emit_alu(&mut self, clk: u32, opcode: Opcode, a: u32, b: u32, c: u32) {
        let event = AluEvent {
            clk,
            opcode,
            a,
            b,
            c,
        };
        match opcode {
            Opcode::ADD | Opcode::ADDI => {
                self.add_events.push(event);
            }
            Opcode::SUB => {
                self.sub_events.push(event);
            }
            Opcode::XOR | Opcode::XORI | Opcode::OR | Opcode::ORI | Opcode::AND | Opcode::ANDI => {
                self.bitwise_events.push(event);
            }
            _ => {}
        }
    }

    /// Execute the given instruction over the current state of the runtime.
    fn execute(&mut self, instruction: Instruction) {
        let pc = self.pc;
        let (mut a, mut b, mut c, mut memory_value): (u32, u32, u32, Option<u32>) =
            (u32::MAX, u32::MAX, u32::MAX, None);
        match instruction.opcode {
            // R-type instructions.
            Opcode::ADD => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b.wrapping_add(c);
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SUB => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b.wrapping_sub(c);
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::XOR => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b ^ c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::OR => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b | c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::AND => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b & c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLL => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b << c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SRL => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b >> c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SRA => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = (b as i32 >> c) as u32;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLT => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = if (b as i32) < (c as i32) { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLTU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = if b < c { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }

            // I-type instructions.
            Opcode::ADDI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b.wrapping_add(c);
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::XORI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b ^ c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::ORI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b | c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::ANDI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b & c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLLI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b << c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SRLI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b >> c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SRAI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = (b as i32 >> c) as u32;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLTI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = if (b as i32) < (c as i32) { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLTIU => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = if b < c { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }

            // Load instructions
            Opcode::LB => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                memory_value = Some(self.mr(addr));
                a = (memory_value.unwrap() as i8) as u32;
                self.rw(rd, a);
            }
            Opcode::LH => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                memory_value = Some(self.mr(addr));
                a = (memory_value.unwrap() as i16) as u32;
                self.rw(rd, a);
            }
            Opcode::LW => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                memory_value = Some(self.mr(addr));
                a = memory_value.unwrap();
                self.rw(rd, a);
            }
            Opcode::LBU => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                memory_value = Some(self.mr(addr));
                let a = (memory_value.unwrap() as u8) as u32;
                self.rw(rd, a);
            }
            Opcode::LHU => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                memory_value = Some(self.mr(addr));
                let a = (memory_value.unwrap() as u16) as u32;
                self.rw(rd, a);
            }

            // S-type instructions.
            Opcode::SB => {
                let (rs1, rs2, imm) = instruction.s_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                let addr = b.wrapping_add(c);
                let value = (a as u8) as u32;
                memory_value = Some(value);
                self.mw(addr, value);
            }
            Opcode::SH => {
                let (rs1, rs2, imm) = instruction.s_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                let addr = b.wrapping_add(c);
                let value = (a as u16) as u32;
                memory_value = Some(value);
                self.mw(addr, value);
            }
            Opcode::SW => {
                let (rs1, rs2, imm) = instruction.s_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                let addr = b.wrapping_add(c);
                let value = a;
                memory_value = Some(value);
                self.mw(addr, value);
            }

            // B-type instructions.
            Opcode::BEQ => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if a == b {
                    self.pc = self.pc.wrapping_add(c);
                }
            }
            Opcode::BNE => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if self.rr(rs1) != self.rr(rs2) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BLT => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if (self.rr(rs1) as i32) < (self.rr(rs2) as i32) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BGE => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if (self.rr(rs1) as i32) >= (self.rr(rs2) as i32) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BLTU => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if self.rr(rs1) < self.rr(rs2) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BGEU => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if self.rr(rs1) >= self.rr(rs2) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }

            // Jump instructions.
            Opcode::JAL => {
                let (rd, imm) = instruction.j_type();
                (b, c) = (imm, 0);
                a = self.pc + 4;
                self.rw(rd, a);
                self.pc = self.pc.wrapping_add(imm);
            }
            Opcode::JALR => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = self.pc + 4;
                self.rw(rd, a);
                self.pc = b.wrapping_add(c);
            }

            // Upper immediate instructions.
            Opcode::LUI => {
                let (rd, imm) = instruction.u_type();
                (b, c) = (imm, 12); // Note that we'll special-case this in the CPU table
                a = b << 12;
                self.rw(rd, a);
            }
            Opcode::AUIPC => {
                let (rd, imm) = instruction.u_type();
                (b, c) = (imm, imm << 12); // Note that we'll special-case this in the CPU table
                a = self.pc.wrapping_add(b << 12);
                self.rw(rd, a);
            }

            // System instructions.
            Opcode::ECALL => {
                todo!()
            }
            Opcode::EBREAK => {
                todo!()
            }

            // Multiply instructions.
            Opcode::MUL => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b.wrapping_mul(c);
                self.rw(rd, a);
            }
            Opcode::MULH => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = ((b as i64).wrapping_mul(c as i64) >> 32) as u32;
                self.rw(rd, a);
            }
            Opcode::MULSU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = ((b as i64).wrapping_mul(c as i64) >> 32) as u32;
                self.rw(rd, a);
            }
            Opcode::MULU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = ((b as u64).wrapping_mul(c as u64) >> 32) as u32;
                self.rw(rd, a);
            }
            Opcode::DIV => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = (b as i32).wrapping_div(c as i32) as u32;
                self.rw(rd, a);
            }
            Opcode::DIVU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b.wrapping_div(c);
                self.rw(rd, a);
            }
            Opcode::REM => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1) as i32, self.rr(rs2) as i32);
                let a = (b as i32).wrapping_rem(c as i32) as u32;
                self.rw(rd, a);
            }
            Opcode::REMU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b.wrapping_rem(c);
                self.rw(rd, a);
            }
            Opcode::UNIMP => {
                println!("UNIMP encountered, ignoring");
            }
        }

        // Emit the CPU event for this cycle.
        self.emit_cpu(self.clk, pc, instruction, a, b, c, memory_value);
    }

    /// Execute the program.
    pub fn run(&mut self) {
        // Set %x2 to the size of memory when the CPU is initialized.
        self.rw(Register::X2, 1024 * 1024 * 8);

        // Set the return address to the end of the program.
        self.rw(Register::X1, (self.program.len() * 4) as u32);

        while self.pc < (self.program.len() * 4) as u32 {
            // Fetch the instruction at the current program counter.
            let instruction = self.fetch();

            // Execute the instruction.
            self.execute(instruction);

            // Increment the program counter by 4.
            self.pc = self.pc + 4;

            // Increment the clock.
            self.clk += 1;
        }
    }

    /// Prove the program.
    #[allow(unused)]
    pub fn prove<F: PrimeField>(&mut self) {
        // Initialize chips.
        let program = ProgramChip::new();
        let cpu = CpuChip::new();
        let add = AddChip::new();
        let sub = SubChip::new();
        let bitwise = BitwiseChip::new();

        // Generate the trace for the program chip.
        let program_trace: RowMajorMatrix<F> = program.generate_trace(self);

        // Generate the trace for the CPU chip and also emit auxiliary events.
        let cpu_trace: RowMajorMatrix<F> = cpu.generate_trace(self);

        // Generate the trace of the add chip.
        let add_trace: RowMajorMatrix<F> = add.generate_trace(self);

        // Generate the trace of the sub chip.
        let sub_trace: RowMajorMatrix<F> = sub.generate_trace(self);

        // Generate the trace of the bitwise chip.
        let bitwise_trace: RowMajorMatrix<F> = bitwise.generate_trace(self);

        // Generate the proof.
        // multiprove(vec![program, cpu, memory, alu];
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
pub mod tests {
    use p3_baby_bear::BabyBear;

    use crate::runtime::instruction::Instruction;
    use crate::runtime::runtime::Register;
    use crate::runtime::runtime::Runtime;

    use super::Opcode;

    pub fn get_simple_program() -> Vec<Instruction> {
        // int main() {
        //     int a = 5;
        //     int b = 8;
        //     int result = a + b;
        //     return 0;
        //   }
        // main:
        // addi    sp,sp,-32
        // sw      s0,28(sp)
        // addi    s0,sp,32
        // li      a5,5
        // sw      a5,-20(s0)
        // li      a5,8
        // sw      a5,-24(s0)
        // lw      a4,-20(s0)
        // lw      a5,-24(s0)
        // add     a5,a4,a5
        // sw      a5,-28(s0)
        // lw      a5,-28(s0)
        // mv      a0,a5
        // lw      s0,28(sp)
        // addi    sp,sp,32
        // jr      ra
        // Mapping taken from here: https://en.wikichip.org/wiki/risc-v/registers
        let SP = Register::X2 as u32;
        let X0 = Register::X0 as u32;
        let S0 = Register::X8 as u32;
        let A0 = Register::X10 as u32;
        let A5 = Register::X15 as u32;
        let A4 = Register::X14 as u32;
        let _RA = Register::X1 as u32;
        let code = vec![
            Instruction::new(Opcode::ADDI, SP, SP, (-32i32) as u32),
            Instruction::new(Opcode::SW, S0, SP, 28),
            Instruction::new(Opcode::ADDI, S0, SP, 32),
            Instruction::new(Opcode::ADDI, A5, X0, 5),
            Instruction::new(Opcode::SW, A5, S0, (-20i32) as u32),
            Instruction::new(Opcode::ADDI, A5, X0, 8),
            Instruction::new(Opcode::SW, A5, S0, (-24i32) as u32),
            Instruction::new(Opcode::LW, A4, S0, (-20i32) as u32),
            Instruction::new(Opcode::LW, A5, S0, (-24i32) as u32),
            Instruction::new(Opcode::ADD, A5, A4, A5),
            Instruction::new(Opcode::SW, A5, S0, (-28i32) as u32),
            Instruction::new(Opcode::LW, A5, S0, (-28i32) as u32),
            Instruction::new(Opcode::ADDI, A0, A5, 0),
            Instruction::new(Opcode::LW, S0, SP, 28),
            Instruction::new(Opcode::ADDI, SP, SP, 32),
            // Instruction::new(Opcode::JALR, X0, RA, 0), // Commented this out because JAL is not working properly right now.
        ];
        code
    }

    #[test]
    fn SIMPLE_PROGRAM() {
        let code = get_simple_program();
        let mut runtime: Runtime = Runtime::new(code);
        runtime.run();
    }

    #[test]
    fn ADD() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::ADD, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        runtime.prove::<BabyBear>();
        assert_eq!(runtime.registers()[Register::X31 as usize], 42);
    }

    #[test]
    fn SUB() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sub x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SUB, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        runtime.prove::<BabyBear>();
        assert_eq!(runtime.registers()[Register::X31 as usize], 32);
    }

    #[test]
    fn XOR() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     xor x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::XOR, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        runtime.prove::<BabyBear>();
        assert_eq!(runtime.registers()[Register::X31 as usize], 32);
    }

    #[test]
    fn OR() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     or x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::OR, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        runtime.prove::<BabyBear>();
        assert_eq!(runtime.registers()[Register::X31 as usize], 37);
    }

    #[test]
    fn AND() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     and x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::AND, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        runtime.prove::<BabyBear>();
        assert_eq!(runtime.registers()[Register::X31 as usize], 5);
    }

    #[test]
    fn SLL() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sll x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SLL, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 1184);
    }

    #[test]
    fn SRL() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     srl x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SRL, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 1);
    }

    #[test]
    fn SRA() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sra x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SRA, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 1);
    }

    #[test]
    fn SLT() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     slt x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SLT, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn SLTU() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sltu x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SLTU, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn ADDI() {
        //     addi x29, x0, 5
        //     addi x30, x29, 37
        //     addi x31, x30, 42
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 29, 37),
            Instruction::new(Opcode::ADDI, 31, 30, 42),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 84);
    }

    #[test]
    fn ADDI_NEGATIVE() {
        //     addi x29, x0, 5
        //     addi x30, x29, -1
        //     addi x31, x30, 4
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 29, 0xffffffff),
            Instruction::new(Opcode::ADDI, 31, 30, 4),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 5 - 1 + 4);
    }

    #[test]
    fn XORI() {
        //     addi x29, x0, 5
        //     xori x30, x29, 37
        //     xori x31, x30, 42
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::XORI, 30, 29, 37),
            Instruction::new(Opcode::XORI, 31, 30, 42),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        runtime.prove::<BabyBear>();
        assert_eq!(runtime.registers()[Register::X31 as usize], 10);
    }

    #[test]
    fn ORI() {
        //     addi x29, x0, 5
        //     ori x30, x29, 37
        //     ori x31, x30, 42
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ORI, 30, 29, 37),
            Instruction::new(Opcode::ORI, 31, 30, 42),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        runtime.prove::<BabyBear>();
        assert_eq!(runtime.registers()[Register::X31 as usize], 47);
    }

    #[test]
    fn ANDI() {
        //     addi x29, x0, 5
        //     andi x30, x29, 37
        //     andi x31, x30, 42
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ANDI, 30, 29, 37),
            Instruction::new(Opcode::ANDI, 31, 30, 42),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        runtime.prove::<BabyBear>();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn SLLI() {
        //     addi x29, x0, 5
        //     slli x31, x29, 37
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::SLLI, 31, 29, 4),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 80);
    }

    #[test]
    fn SRLI() {
        //    addi x29, x0, 5
        //    srli x31, x29, 37
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 42),
            Instruction::new(Opcode::SRLI, 31, 29, 4),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 2);
    }

    #[test]
    fn SRAI() {
        //   addi x29, x0, 5
        //   srai x31, x29, 37
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 42),
            Instruction::new(Opcode::SRAI, 31, 29, 4),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 2);
    }

    #[test]
    fn SLTI() {
        //   addi x29, x0, 5
        //   slti x31, x29, 37
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 42),
            Instruction::new(Opcode::SLTI, 31, 29, 37),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn SLTIU() {
        //   addi x29, x0, 5
        //   sltiu x31, x29, 37
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 42),
            Instruction::new(Opcode::SLTIU, 31, 29, 37),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }
}
