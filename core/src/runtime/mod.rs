mod instruction;
mod opcode;
mod register;

use crate::alu::AluEvent;
use crate::cpu::CpuEvent;
use crate::disassembler::{Instruction, Opcode, Register};
use std::collections::BTreeMap;

use crate::memory::{MemOp, MemoryEvent};

/// An implementation of a runtime for the Curta VM.
///
/// The runtime is responsible for executing a user program and tracing important events which occur
/// during execution (i.e., memory reads, alu operations, etc).
///
/// For more information on the RV32IM instruction set, see the following:
/// https://www.cs.sfu.ca/~ashriram/Courses/CS295/assets/notebooks/RISCV/RISCV_CARD.pdf
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

    /// A trace of the SLL, SLLI, SRL, SRLI, SRA, and SRAI events.
    pub shift_events: Vec<AluEvent>,

    /// A trace of the SLT, SLTI, SLTU, and SLTIU events.
    pub lt_events: Vec<AluEvent>,
}

impl Runtime {
    // Create a new runtime
    pub fn new(program: Vec<Instruction>, init_pc: u32) -> Self {
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
            shift_events: Vec::new(),
            lt_events: Vec::new(),
        }
    }

    /// Read from memory.
    fn mr(&mut self, addr: u32) -> u32 {
        let addr_word_aligned = addr - addr % 4;
        let value = match self.memory.get(&addr_word_aligned) {
            Some(value) => *value,
            None => 0,
        };
        self.emit_memory(self.clk, addr_word_aligned, MemOp::Read, value);
        return value;
    }

    /// Write to memory.
    fn mw(&mut self, addr: u32, value: u32) {
        let addr_word_aligned = addr - addr % 4;
        self.memory.insert(addr_word_aligned, value);
        self.emit_memory(self.clk, addr_word_aligned, MemOp::Write, value);
    }

    /// Convert a register to a memory address.
    fn r2m(&self, register: Register) -> u32 {
        // We have to word-align the register memory address.
        u32::from_be_bytes([0xFF, 0xFF, 0xFF, (register as u8) * 4])
    }

    /// Read from register.
    fn rr(&mut self, register: Register) -> u32 {
        let addr = self.r2m(register);
        self.mr(addr)
    }

    /// Write to register.
    fn rw(&mut self, register: Register, value: u32) {
        if register == Register::X0 {
            // We don't write to %x0. See 2.6 Load and Store Instruction on
            // P.18 of the RISC-V spec.
            return;
        }
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
        memory_store_value: Option<u32>,
    ) {
        self.cpu_events.push(CpuEvent {
            clk: clk,
            pc: pc,
            instruction,
            a,
            b,
            c,
            memory_value,
            memory_store_value,
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
            Opcode::ADD => {
                self.add_events.push(event);
            }
            Opcode::SUB => {
                self.sub_events.push(event);
            }
            Opcode::XOR | Opcode::OR | Opcode::AND => {
                self.bitwise_events.push(event);
            }
            Opcode::SLL | Opcode::SRL | Opcode::SRA => {
                self.shift_events.push(event);
            }
            Opcode::SLT | Opcode::SLTU => {
                self.lt_events.push(event);
            }
            _ => {}
        }
    }

    /// Fetch the destination register and input operand values for an ALU instruction.
    fn alu_rr(&mut self, instruction: Instruction) -> (Register, u32, u32) {
        if instruction.is_r_type() {
            let (rd, rs1, rs2) = instruction.r_type();
            let (b, c) = (self.rr(rs1), self.rr(rs2));
            (rd, b, c)
        } else {
            let (rd, rs1, imm) = instruction.i_type();
            let (b, c) = (self.rr(rs1), imm);
            (rd, b, c)
        }
    }

    /// Fetch the destination register, address, and memory value for a load instruction.
    fn load_rr(&mut self, instruction: Instruction) -> (Register, u32, Option<u32>) {
        let (rd, rs1, imm) = instruction.i_type();
        let (b, c) = (self.rr(rs1), imm);
        let addr = b.wrapping_add(c);
        let memory_value = Some(self.mr(addr));
        (rd, addr, memory_value)
    }

    /// Execute the given instruction over the current state of the runtime.
    fn execute(&mut self, instruction: Instruction) {
        let pc = self.pc;
        let rd: Register;
        let addr: u32;
        let (mut a, mut b, mut c, mut memory_value, mut memory_store_value): (
            u32,
            u32,
            u32,
            Option<u32>,
            Option<u32>,
        ) = (u32::MAX, u32::MAX, u32::MAX, None, None);

        let mut next_pc = self.pc.wrapping_add(4);
        match instruction.opcode {
            // Arithmetic instructions.
            Opcode::ADD => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_add(c);
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SUB => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_sub(c);
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::XOR => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b ^ c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::OR => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b | c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::AND => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b & c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b << c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SRL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b >> c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SRA => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (b as i32 >> c) as u32;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLT => {
                (rd, b, c) = self.alu_rr(instruction);
                a = if (b as i32) < (c as i32) { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLTU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = if b < c { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }

            // Load instructions.
            Opcode::LB => {
                (rd, addr, memory_value) = self.load_rr(instruction);
                let value = (memory_value.unwrap()).to_le_bytes()[(addr % 4) as usize];
                a = ((value as i8) as i32) as u32;
                self.rw(rd, a);
            }
            Opcode::LH => {
                (rd, addr, memory_value) = self.load_rr(instruction);
                assert_eq!(addr % 2, 0, "LH");
                let offset = addr % 4;
                let value = if offset == 0 {
                    memory_value.unwrap() & 0x0000FFFF
                } else {
                    memory_value.unwrap() & 0xFFFF0000
                };
                a = ((value as i16) as i32) as u32;
                self.rw(rd, a);
            }
            Opcode::LW => {
                (rd, addr, memory_value) = self.load_rr(instruction);
                assert_eq!(addr % 4, 0, "LW");
                a = memory_value.unwrap();
                self.rw(rd, a);
            }
            Opcode::LBU => {
                (rd, addr, memory_value) = self.load_rr(instruction);
                let value = (memory_value.unwrap()).to_le_bytes()[(addr % 4) as usize];
                a = (value as u8) as u32;
                self.rw(rd, a);
            }
            Opcode::LHU => {
                (rd, addr, memory_value) = self.load_rr(instruction);
                assert_eq!(addr % 2, 0, "LHU");
                let offset = addr % 4;
                let value = if offset == 0 {
                    memory_value.unwrap() & 0x0000FFFF
                } else {
                    memory_value.unwrap() & 0xFFFF0000
                };
                a = (value as u16) as u32;
                self.rw(rd, a);
            }

            // Store instructions.
            Opcode::SB => {
                let (rs1, rs2, imm) = instruction.s_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                let addr = b.wrapping_add(c);
                memory_value = Some(self.mr(addr));
                let offset = addr % 4;
                let value = if offset == 0 {
                    (a & 0x000000FF) + (memory_value.unwrap() & 0xFFFFFF00)
                } else if offset == 1 {
                    (a & 0x000000FF) << 8 + (memory_value.unwrap() & 0xFFFF00FF)
                } else if offset == 2 {
                    (a & 0x000000FF) << 16 + (memory_value.unwrap() & 0xFF00FFFF)
                } else {
                    (a & 0x000000FF) << 24 + (memory_value.unwrap() & 0x00FFFFFF)
                };
                memory_store_value = Some(value);
                self.mw(addr, value);
            }
            Opcode::SH => {
                let (rs1, rs2, imm) = instruction.s_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                let addr = b.wrapping_add(c);
                assert_eq!(addr % 2, 0, "SH");
                memory_value = Some(self.mr(addr));
                let offset = addr % 2;
                let value = if offset == 0 {
                    (memory_value.unwrap() & 0xFFFF0000) + (a & 0x0000FFFF)
                } else {
                    (memory_value.unwrap() & 0x0000FFFF) + (a & 0x0000FFFF) << 16
                };
                memory_store_value = Some(value);
                self.mw(addr, value);
            }
            Opcode::SW => {
                let (rs1, rs2, imm) = instruction.s_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                let addr = b.wrapping_add(c);
                assert_eq!(addr % 4, 0, "SW");
                memory_value = Some(self.mr(addr)); // We read the address even though we will overwrite it fully.
                let value = a;
                memory_store_value = Some(value);
                self.mw(addr, value);
            }

            // B-type instructions.
            Opcode::BEQ => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if a == b {
                    next_pc = self.pc.wrapping_add(c);
                }
            }
            Opcode::BNE => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if a != b {
                    next_pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BLT => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if (a as i32) < (b as i32) {
                    next_pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BGE => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if (a as i32) >= (b as i32) {
                    next_pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BLTU => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if a < b {
                    next_pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BGEU => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if a >= b {
                    next_pc = self.pc.wrapping_add(imm);
                }
            }

            // Jump instructions.
            Opcode::JAL => {
                let (rd, imm) = instruction.j_type();
                (b, c) = (imm, 0);
                a = self.pc + 4;
                self.rw(rd, a);
                next_pc = self.pc.wrapping_add(imm);
            }
            Opcode::JALR => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = self.pc + 4;
                self.rw(rd, a);
                next_pc = b.wrapping_add(c);
            }

            // Upper immediate instructions.
            Opcode::AUIPC => {
                let (rd, imm) = instruction.u_type();
                (b, c) = (imm, imm << 12);
                a = self.pc.wrapping_add(b << 12);
                self.rw(rd, a);
            }

            // System instructions.
            Opcode::ECALL => {
                // While not all ECALLs obviously halt the CPU, we will for now halt. We need to
                // come back to this and figure out how to handle this properly.
                println!("ECALL encountered! Halting!");
                next_pc = self.program.len() as u32 * 4;
            }

            Opcode::EBREAK => {
                todo!()
            }

            // Multiply instructions.
            Opcode::MUL => {
                // MUL performs an 32-bit×32-bit multiplication and places the
                // lower 32 bits in the destination register.
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_mul(c);
                self.rw(rd, a);
            }
            Opcode::MULH => {
                // MULH performs the same multiplication, but returns the upper
                // 32 bits of the product. (signed x signed)
                (rd, b, c) = self.alu_rr(instruction);
                a = (((b as i32) as i64).wrapping_mul((c as i32) as i64) >> 32) as u32;
                self.rw(rd, a);
            }
            Opcode::MULHU => {
                // MULH performs the same multiplication, but returns the upper
                // 32 bits of the product. (unsigned x unsigned)
                (rd, b, c) = self.alu_rr(instruction);
                a = ((b as u64).wrapping_mul(c as u64) >> 32) as u32;
                self.rw(rd, a);
            }
            Opcode::MULHSU => {
                // MULH performs the same multiplication, but returns the upper
                // 32 bits of the product. (signed x unsigned)
                (rd, b, c) = self.alu_rr(instruction);
                a = (((b as i32) as i64).wrapping_mul(c as i64) >> 32) as u32;
                self.rw(rd, a);
            }
            Opcode::DIV => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = u32::MAX;
                } else {
                    a = (b as i32).wrapping_div(c as i32) as u32;
                }
                self.rw(rd, a);
            }
            Opcode::DIVU => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = u32::MAX;
                } else {
                    a = b.wrapping_div(c);
                }
                self.rw(rd, a);
            }
            Opcode::REM => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = b;
                } else {
                    a = (b as i32).wrapping_rem(c as i32) as u32;
                }
                self.rw(rd, a);
            }
            Opcode::REMU => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = b;
                } else {
                    a = b.wrapping_rem(c);
                }
                self.rw(rd, a);
            }

            // Precompile instructions.
            Opcode::HALT => {
                todo!()
            }
            Opcode::LWA => {
                todo!()
            }
            Opcode::PRECOMPILE => {
                todo!()
            }

            Opcode::UNIMP => {
                // See https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#instruction-aliases
                panic!("UNIMP encountered, we should never get here.");
            }
        }
        self.pc = next_pc;

        // Emit the CPU event for this cycle.
        self.emit_cpu(
            self.clk,
            pc,
            instruction,
            a,
            b,
            c,
            memory_value,
            memory_store_value,
        );
    }

    /// Execute the program.
    pub fn run(&mut self) {
        // Set %x2 to the size of memory when the CPU is initialized.
        self.rw(Register::X2, 1024 * 1024 * 8);

        // Set the return address to the end of the program.
        self.rw(Register::X1, (self.program.len() * 4) as u32);

        self.clk += 1;
        while self.pc < (self.program.len() * 4) as u32 {
            // Fetch the instruction at the current program counter.
            let instruction = self.fetch();

            // Execute the instruction.
            self.execute(instruction);

            // Increment the clock.
            self.clk += 1;
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
pub mod tests {
    use crate::disassembler::{disassemble_from_elf, Instruction, Opcode, Register};

    use super::Runtime;

    #[test]
    fn test_fibonacci() {
        let (program, pc) = disassemble_from_elf("../programs/fib.s");
        let mut runtime = Runtime::new(program, pc);
        runtime.run();
        println!("{:?}", runtime.registers());
    }

    #[test]
    fn test_simple_program() {
        let program = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        let mut runtime = Runtime::new(program, 0);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 42);
    }
}

// #[cfg(test)]
// #[allow(non_snake_case)]
// pub mod tests {
//     use super::Opcode;
//     use super::Register;
//     use super::Runtime;
//     use crate::disassembler::dissasemble;
//     use crate::runtime::instruction::Instruction;
//     use p3_baby_bear::BabyBear;
//     use p3_challenger::DuplexChallenger;
//     use p3_commit::ExtensionMmcs;
//     use p3_dft::Radix2DitParallel;
//     use p3_field::extension::BinomialExtensionField;
//     use p3_field::Field;
//     use p3_fri::FriBasedPcs;
//     use p3_fri::FriConfigImpl;
//     use p3_fri::FriLdt;
//     use p3_keccak::Keccak256Hash;
//     use p3_ldt::QuotientMmcs;
//     use p3_mds::coset_mds::CosetMds;
//     use p3_merkle_tree::FieldMerkleTreeMmcs;
//     use p3_poseidon2::DiffusionMatrixBabybear;
//     use p3_poseidon2::Poseidon2;
//     use p3_symmetric::CompressionFunctionFromHasher;
//     use p3_symmetric::SerializingHasher32;
//     use p3_uni_stark::StarkConfigImpl;
//     use rand::thread_rng;
//     use std::io::Read;
//     use std::path::Path;

//     pub fn get_simple_program() -> Vec<Instruction> {
//         // int main() {
//         //     int a = 5;
//         //     int b = 8;
//         //     int result = a + b;
//         //     return 0;
//         //   }
//         // main:
//         // addi    sp,sp,-32
//         // sw      s0,28(sp)
//         // addi    s0,sp,32
//         // li      a5,5
//         // sw      a5,-20(s0)
//         // li      a5,8
//         // sw      a5,-24(s0)
//         // lw      a4,-20(s0)
//         // lw      a5,-24(s0)
//         // add     a5,a4,a5
//         // sw      a5,-28(s0)
//         // lw      a5,-28(s0)
//         // mv      a0,a5
//         // lw      s0,28(sp)
//         // addi    sp,sp,32
//         // jr      ra
//         // Mapping taken from here: https://en.wikichip.org/wiki/risc-v/registers
//         let SP = Register::X2 as u32;
//         let X0 = Register::X0 as u32;
//         let S0 = Register::X8 as u32;
//         let A0 = Register::X10 as u32;
//         let A5 = Register::X15 as u32;
//         let A4 = Register::X14 as u32;
//         let _RA = Register::X1 as u32;
//         let code = vec![
//             Instruction::new(Opcode::ADDI, SP, SP, (-32i32) as u32),
//             Instruction::new(Opcode::SW, S0, SP, 28),
//             Instruction::new(Opcode::ADDI, S0, SP, 32),
//             Instruction::new(Opcode::ADDI, A5, X0, 5),
//             Instruction::new(Opcode::SW, A5, S0, (-20i32) as u32),
//             Instruction::new(Opcode::ADDI, A5, X0, 8),
//             Instruction::new(Opcode::SW, A5, S0, (-24i32) as u32),
//             Instruction::new(Opcode::LW, A4, S0, (-20i32) as u32),
//             Instruction::new(Opcode::LW, A5, S0, (-24i32) as u32),
//             Instruction::new(Opcode::ADD, A5, A4, A5),
//             Instruction::new(Opcode::SW, A5, S0, (-28i32) as u32),
//             Instruction::new(Opcode::LW, A5, S0, (-28i32) as u32),
//             Instruction::new(Opcode::ADDI, A0, A5, 0),
//             Instruction::new(Opcode::LW, S0, SP, 28),
//             Instruction::new(Opcode::ADDI, SP, SP, 32),
//             // Instruction::new(Opcode::JALR, X0, RA, 0), // Commented this out because JAL is not working properly right now.
//         ];
//         code
//     }

//     fn get_fibonacci_program() -> (Vec<Instruction>, u32) {
//         let mut elf_code = Vec::new();
//         let path = Path::new("").join("../programs/fib").with_extension("s");
//         std::fs::File::open(path)
//             .expect("Failed to open input file")
//             .read_to_end(&mut elf_code)
//             .expect("Failed to read from input file");

//         // Parse ELF code.
//         dissasemble(&elf_code)
//     }

//     #[test]
//     fn SIMPLE_PROGRAM() {
//         let code = get_simple_program();
//         let mut runtime = Runtime::new(code, 0);
//         runtime.run();
//     }

//     #[test]
//     fn fibonacci_program() {
//         let (code, pc) = get_fibonacci_program();
//         let mut runtime: Runtime = Runtime::new(code, pc);
//         runtime.run();
//     }

//     #[test]
//     fn basic_pogram() {
//         // main:
//         //     addi x29, x0, 5
//         //     addi x30, x0, 37
//         //     add x31, x30, x29
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::ADD, 31, 30, 29),
//         ];
//         let mut runtime: Runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 42);
//     }

//     #[test]
//     fn prove_fibonacci() {
//         let (program, pc) = get_fibonacci_program();
//         prove(program, pc);
//     }

//     #[test]
//     fn prove_simple() {
//         let program = get_simple_program();
//         prove(program, 0);
//     }

//     #[test]
//     fn prove_basic() {
//         // main:
//         //     addi x29, x0, 5
//         //     addi x30, x0, 37
//         //     add x31, x30, x29
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::ADD, 31, 30, 29),
//         ];
//         prove(program, 0);
//     }

//     fn prove(program: Vec<Instruction>, init_pc: u32) {
//         type Val = BabyBear;
//         type Domain = Val;
//         type Challenge = BinomialExtensionField<Val, 4>;
//         type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

//         type MyMds = CosetMds<Val, 16>;
//         let mds = MyMds::default();

//         type Perm = Poseidon2<Val, MyMds, DiffusionMatrixBabybear, 16, 5>;
//         let perm = Perm::new_from_rng(8, 22, mds, DiffusionMatrixBabybear, &mut thread_rng());

//         type MyHash = SerializingHasher32<Keccak256Hash>;
//         let hash = MyHash::new(Keccak256Hash {});

//         type MyCompress = CompressionFunctionFromHasher<Val, MyHash, 2, 8>;
//         let compress = MyCompress::new(hash);

//         type ValMmcs = FieldMerkleTreeMmcs<Val, MyHash, MyCompress, 8>;
//         let val_mmcs = ValMmcs::new(hash, compress);

//         type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
//         let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

//         type Dft = Radix2DitParallel;
//         let dft = Dft {};

//         type Challenger = DuplexChallenger<Val, Perm, 16>;

//         type Quotient = QuotientMmcs<Domain, Challenge, ValMmcs>;
//         type MyFriConfig = FriConfigImpl<Val, Challenge, Quotient, ChallengeMmcs, Challenger>;
//         let fri_config = MyFriConfig::new(40, challenge_mmcs);
//         let ldt = FriLdt { config: fri_config };

//         type Pcs = FriBasedPcs<MyFriConfig, ValMmcs, Dft, Challenger>;
//         type MyConfig = StarkConfigImpl<Val, Challenge, PackedChallenge, Pcs, Challenger>;

//         let pcs = Pcs::new(dft, val_mmcs, ldt);
//         let config = StarkConfigImpl::new(pcs);
//         let mut challenger = Challenger::new(perm.clone());

//         let mut runtime = Runtime::new(program, init_pc);
//         runtime.run();
//         runtime.prove::<_, _, MyConfig>(&config, &mut challenger);
//     }

//     #[test]
//     fn ADD() {
//         // main:
//         //     addi x29, x0, 5
//         //     addi x30, x0, 37
//         //     add x31, x30, x29
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::ADDI, 30, 0, 37),
//             Instruction::new(Opcode::ADD, 31, 30, 29),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();

//         assert_eq!(runtime.registers()[Register::X31 as usize], 42);
//     }

//     #[test]
//     fn SUB() {
//         //     addi x29, x0, 5
//         //     addi x30, x0, 37
//         //     sub x31, x30, x29
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::ADDI, 30, 0, 37),
//             Instruction::new(Opcode::SUB, 31, 30, 29),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 32);
//     }

//     #[test]
//     fn XOR() {
//         //     addi x29, x0, 5
//         //     addi x30, x0, 37
//         //     xor x31, x30, x29
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::ADDI, 30, 0, 37),
//             Instruction::new(Opcode::XOR, 31, 30, 29),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 32);
//     }

//     #[test]
//     fn OR() {
//         //     addi x29, x0, 5
//         //     addi x30, x0, 37
//         //     or x31, x30, x29
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::ADDI, 30, 0, 37),
//             Instruction::new(Opcode::OR, 31, 30, 29),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 37);
//     }

//     #[test]
//     fn AND() {
//         //     addi x29, x0, 5
//         //     addi x30, x0, 37
//         //     and x31, x30, x29
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::ADDI, 30, 0, 37),
//             Instruction::new(Opcode::AND, 31, 30, 29),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 5);
//     }

//     #[test]
//     fn SLL() {
//         //     addi x29, x0, 5
//         //     addi x30, x0, 37
//         //     sll x31, x30, x29
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::ADDI, 30, 0, 37),
//             Instruction::new(Opcode::SLL, 31, 30, 29),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 1184);
//     }

//     #[test]
//     fn SRL() {
//         //     addi x29, x0, 5
//         //     addi x30, x0, 37
//         //     srl x31, x30, x29
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::ADDI, 30, 0, 37),
//             Instruction::new(Opcode::SRL, 31, 30, 29),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 1);
//     }

//     #[test]
//     fn SRA() {
//         //     addi x29, x0, 5
//         //     addi x30, x0, 37
//         //     sra x31, x30, x29
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::ADDI, 30, 0, 37),
//             Instruction::new(Opcode::SRA, 31, 30, 29),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 1);
//     }

//     #[test]
//     fn SLT() {
//         //     addi x29, x0, 5
//         //     addi x30, x0, 37
//         //     slt x31, x30, x29
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::ADDI, 30, 0, 37),
//             Instruction::new(Opcode::SLT, 31, 30, 29),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 0);
//     }

//     #[test]
//     fn SLTU() {
//         //     addi x29, x0, 5
//         //     addi x30, x0, 37
//         //     sltu x31, x30, x29
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::ADDI, 30, 0, 37),
//             Instruction::new(Opcode::SLTU, 31, 30, 29),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 0);
//     }

//     #[test]
//     fn ADDI() {
//         //     addi x29, x0, 5
//         //     addi x30, x29, 37
//         //     addi x31, x30, 42
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::ADDI, 30, 29, 37),
//             Instruction::new(Opcode::ADDI, 31, 30, 42),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 84);
//     }

//     #[test]
//     fn ADDI_NEGATIVE() {
//         //     addi x29, x0, 5
//         //     addi x30, x29, -1
//         //     addi x31, x30, 4
//         let code = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::ADDI, 30, 29, 0xffffffff),
//             Instruction::new(Opcode::ADDI, 31, 30, 4),
//         ];
//         let mut runtime = Runtime::new(code, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 5 - 1 + 4);
//     }

//     #[test]
//     fn XORI() {
//         //     addi x29, x0, 5
//         //     xori x30, x29, 37
//         //     xori x31, x30, 42
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::XORI, 30, 29, 37),
//             Instruction::new(Opcode::XORI, 31, 30, 42),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();

//         assert_eq!(runtime.registers()[Register::X31 as usize], 10);
//     }

//     #[test]
//     fn ORI() {
//         //     addi x29, x0, 5
//         //     ori x30, x29, 37
//         //     ori x31, x30, 42
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::ORI, 30, 29, 37),
//             Instruction::new(Opcode::ORI, 31, 30, 42),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();

//         assert_eq!(runtime.registers()[Register::X31 as usize], 47);
//     }

//     #[test]
//     fn ANDI() {
//         //     addi x29, x0, 5
//         //     andi x30, x29, 37
//         //     andi x31, x30, 42
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::ANDI, 30, 29, 37),
//             Instruction::new(Opcode::ANDI, 31, 30, 42),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();

//         assert_eq!(runtime.registers()[Register::X31 as usize], 0);
//     }

//     #[test]
//     fn SLLI() {
//         //     addi x29, x0, 5
//         //     slli x31, x29, 37
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 5),
//             Instruction::new(Opcode::SLLI, 31, 29, 4),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 80);
//     }

//     #[test]
//     fn SRLI() {
//         //    addi x29, x0, 5
//         //    srli x31, x29, 37
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 42),
//             Instruction::new(Opcode::SRLI, 31, 29, 4),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 2);
//     }

//     #[test]
//     fn SRAI() {
//         //   addi x29, x0, 5
//         //   srai x31, x29, 37
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 42),
//             Instruction::new(Opcode::SRAI, 31, 29, 4),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 2);
//     }

//     #[test]
//     fn SLTI() {
//         //   addi x29, x0, 5
//         //   slti x31, x29, 37
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 42),
//             Instruction::new(Opcode::SLTI, 31, 29, 37),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 0);
//     }

//     #[test]
//     fn SLTIU() {
//         //   addi x29, x0, 5
//         //   sltiu x31, x29, 37
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 29, 0, 42),
//             Instruction::new(Opcode::SLTIU, 31, 29, 37),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X31 as usize], 0);
//     }

//     #[test]
//     fn JALR() {
//         //   addi x11, x11, 100
//         //   jalr x5, x11, 8
//         //
//         // `JALR rd offset(rs)` reads the value at rs, adds offset to it and uses it as the
//         // destination address. It then stores the address of the next instruction in rd in case
//         // we'd want to come back here.

//         let program = vec![
//             Instruction::new(Opcode::ADDI, 11, 11, 100),
//             Instruction::new(Opcode::JALR, 5, 11, 8),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X5 as usize], 8);
//         assert_eq!(runtime.registers()[Register::X11 as usize], 100);
//         assert_eq!(runtime.pc, 108);
//     }

//     fn simple_op_code_test(opcode: Opcode, expected: u32, a: u32, b: u32) {
//         let program = vec![
//             Instruction::new(Opcode::ADDI, 10, 0, a),
//             Instruction::new(Opcode::ADDI, 11, 0, b),
//             Instruction::new(opcode, 12, 10, 11),
//         ];
//         let mut runtime = Runtime::new(program, 0);
//         runtime.run();
//         assert_eq!(runtime.registers()[Register::X12 as usize], expected);
//     }

//     #[test]
//     fn multiplication_tests() {
//         simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000000, 0x00000000);
//         simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000001, 0x00000001);
//         simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000003, 0x00000007);
//         simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000000, 0xffff8000);
//         simple_op_code_test(Opcode::MULHU, 0x00000000, 0x80000000, 0x00000000);
//         simple_op_code_test(Opcode::MULHU, 0x7fffc000, 0x80000000, 0xffff8000);
//         simple_op_code_test(Opcode::MULHU, 0x0001fefe, 0xaaaaaaab, 0x0002fe7d);
//         simple_op_code_test(Opcode::MULHU, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab);
//         simple_op_code_test(Opcode::MULHU, 0xfe010000, 0xff000000, 0xff000000);
//         simple_op_code_test(Opcode::MULHU, 0xfffffffe, 0xffffffff, 0xffffffff);
//         simple_op_code_test(Opcode::MULHU, 0x00000000, 0xffffffff, 0x00000001);
//         simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000001, 0xffffffff);

//         simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000000, 0x00000000);
//         simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000001, 0x00000001);
//         simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000003, 0x00000007);
//         simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000000, 0xffff8000);
//         simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x80000000, 0x00000000);
//         simple_op_code_test(Opcode::MULHSU, 0x80004000, 0x80000000, 0xffff8000);
//         simple_op_code_test(Opcode::MULHSU, 0xffff0081, 0xaaaaaaab, 0x0002fe7d);
//         simple_op_code_test(Opcode::MULHSU, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab);
//         simple_op_code_test(Opcode::MULHSU, 0xff010000, 0xff000000, 0xff000000);
//         simple_op_code_test(Opcode::MULHSU, 0xffffffff, 0xffffffff, 0xffffffff);
//         simple_op_code_test(Opcode::MULHSU, 0xffffffff, 0xffffffff, 0x00000001);
//         simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000001, 0xffffffff);

//         simple_op_code_test(Opcode::MULH, 0x00000000, 0x00000000, 0x00000000);
//         simple_op_code_test(Opcode::MULH, 0x00000000, 0x00000001, 0x00000001);
//         simple_op_code_test(Opcode::MULH, 0x00000000, 0x00000003, 0x00000007);
//         simple_op_code_test(Opcode::MULH, 0x00000000, 0x00000000, 0xffff8000);
//         simple_op_code_test(Opcode::MULH, 0x00000000, 0x80000000, 0x00000000);
//         simple_op_code_test(Opcode::MULH, 0x00000000, 0x80000000, 0x00000000);
//         simple_op_code_test(Opcode::MULH, 0xffff0081, 0xaaaaaaab, 0x0002fe7d);
//         simple_op_code_test(Opcode::MULH, 0xffff0081, 0x0002fe7d, 0xaaaaaaab);
//         simple_op_code_test(Opcode::MULH, 0x00010000, 0xff000000, 0xff000000);
//         simple_op_code_test(Opcode::MULH, 0x00000000, 0xffffffff, 0xffffffff);
//         simple_op_code_test(Opcode::MULH, 0xffffffff, 0xffffffff, 0x00000001);
//         simple_op_code_test(Opcode::MULH, 0xffffffff, 0x00000001, 0xffffffff);

//         simple_op_code_test(Opcode::MUL, 0x00001200, 0x00007e00, 0xb6db6db7);
//         simple_op_code_test(Opcode::MUL, 0x00001240, 0x00007fc0, 0xb6db6db7);
//         simple_op_code_test(Opcode::MUL, 0x00000000, 0x00000000, 0x00000000);
//         simple_op_code_test(Opcode::MUL, 0x00000001, 0x00000001, 0x00000001);
//         simple_op_code_test(Opcode::MUL, 0x00000015, 0x00000003, 0x00000007);
//         simple_op_code_test(Opcode::MUL, 0x00000000, 0x00000000, 0xffff8000);
//         simple_op_code_test(Opcode::MUL, 0x00000000, 0x80000000, 0x00000000);
//         simple_op_code_test(Opcode::MUL, 0x00000000, 0x80000000, 0xffff8000);
//         simple_op_code_test(Opcode::MUL, 0x0000ff7f, 0xaaaaaaab, 0x0002fe7d);
//         simple_op_code_test(Opcode::MUL, 0x0000ff7f, 0x0002fe7d, 0xaaaaaaab);
//         simple_op_code_test(Opcode::MUL, 0x00000000, 0xff000000, 0xff000000);
//         simple_op_code_test(Opcode::MUL, 0x00000001, 0xffffffff, 0xffffffff);
//         simple_op_code_test(Opcode::MUL, 0xffffffff, 0xffffffff, 0x00000001);
//         simple_op_code_test(Opcode::MUL, 0xffffffff, 0x00000001, 0xffffffff);
//     }
// }
