use std::collections::BTreeMap;

/// An opcode specifies which operation to execute.
pub type Opcode = u8;

/// Register instructions.
pub const ADD: Opcode = 0;
pub const SUB: Opcode = 1;
pub const XOR: Opcode = 2;
pub const OR: Opcode = 3;
pub const AND: Opcode = 4;
pub const SLL: Opcode = 5;
pub const SRL: Opcode = 6;
pub const SRA: Opcode = 7;
pub const SLT: Opcode = 8;
pub const SLTU: Opcode = 9;

/// Immediate instructions.
pub const ADDI: Opcode = 10;
pub const XORI: Opcode = 11;
pub const ORI: Opcode = 12;
pub const ANDI: Opcode = 13;
pub const SLLI: Opcode = 14;
pub const SRLI: Opcode = 15;
pub const SRAI: Opcode = 16;
pub const SLTI: Opcode = 17;
pub const SLTIU: Opcode = 18;

/// Load instructions.
pub const LB: Opcode = 19;
pub const LH: Opcode = 20;
pub const LW: Opcode = 21;
pub const LBU: Opcode = 22;
pub const LHU: Opcode = 23;

/// Store instructions.
pub const SB: Opcode = 24;
pub const SH: Opcode = 25;
pub const SW: Opcode = 26;

/// Branch instructions.
pub const BEQ: Opcode = 27;
pub const BNE: Opcode = 28;
pub const BLT: Opcode = 29;
pub const BGE: Opcode = 30;
pub const BLTU: Opcode = 31;
pub const BGEU: Opcode = 32;

/// Jump instructions.
pub const JAL: Opcode = 33;
pub const JALR: Opcode = 34;
pub const LUI: Opcode = 35;
pub const AUIPC: Opcode = 36;

/// System instructions.
pub const ECALL: Opcode = 37;
pub const EBREAK: Opcode = 38;

/// Multiply instructions.
pub const MUL: Opcode = 39;
pub const MULH: Opcode = 40;
pub const MULSU: Opcode = 41;
pub const MULU: Opcode = 42;
pub const DIV: Opcode = 43;
pub const DIVU: Opcode = 44;
pub const REM: Opcode = 45;
pub const REMU: Opcode = 46;

/// A register stores a 32-bit value used by operations.
pub type Register = u8;

/// General-purpose registers.
pub const X0: Register = 0;
pub const X1: Register = 1;
pub const X2: Register = 2;
pub const X3: Register = 3;
pub const X4: Register = 4;
pub const X5: Register = 5;
pub const X6: Register = 6;
pub const X7: Register = 7;
pub const X8: Register = 8;
pub const X9: Register = 9;
pub const X10: Register = 10;
pub const X11: Register = 11;
pub const X12: Register = 12;
pub const X13: Register = 13;
pub const X14: Register = 14;
pub const X15: Register = 15;
pub const X16: Register = 16;
pub const X17: Register = 17;
pub const X18: Register = 18;
pub const X19: Register = 19;
pub const X20: Register = 20;
pub const X21: Register = 21;
pub const X22: Register = 22;
pub const X23: Register = 23;
pub const X24: Register = 24;
pub const X25: Register = 25;
pub const X26: Register = 26;
pub const X27: Register = 27;
pub const X28: Register = 28;
pub const X29: Register = 29;
pub const X30: Register = 30;
pub const X31: Register = 31;

/// Zero constant.
pub const ZERO: Register = X0;

/// Return address.
pub const RA: Register = X1;

/// Stack pointer.
pub const SP: Register = X2;

/// Global pointer.
pub const GP: Register = X3;

/// Thread pointer.
pub const TP: Register = X4;

/// Temporaries.
pub const T0: Register = X5;
pub const T1: Register = X6;
pub const T2: Register = X7;

/// Saved pointer.
pub const S0: Register = X8;

/// Frame pointer.
pub const FP: Register = X8;

///  Saved register.
pub const S1: Register = X9;

/// Function arguments/return values.
pub const A0: Register = X10;
pub const A1: Register = X11;

/// Function arguments.
pub const A2: Register = X12;
pub const A3: Register = X13;
pub const A4: Register = X14;
pub const A5: Register = X15;
pub const A6: Register = X16;
pub const A7: Register = X17;

/// Saved registers.
pub const S2: Register = X18;
pub const S3: Register = X19;
pub const S4: Register = X20;
pub const S5: Register = X21;
pub const S6: Register = X22;
pub const S7: Register = X23;
pub const S8: Register = X24;
pub const S9: Register = X25;
pub const S10: Register = X26;
pub const S11: Register = X27;

/// Temporaries.
pub const T3: Register = X28;
pub const T4: Register = X29;
pub const T5: Register = X30;
pub const T6: Register = X31;

/// An operand that can either a register or an immediate value.
pub enum RegisterOrImmediate {
    Register(Register),
    Immediate(u32),
}

/// An instruction specifies an operation to execute and the operands.
pub struct Instruction {
    opcode: Opcode,
    a: Register,
    b: Register,
    c: RegisterOrImmediate,
}

pub struct Runtime {
    clk: u32,
    registers: [u32; 32],
    memory: BTreeMap<u32, u32>,
}

impl Runtime {
    pub fn new() -> Self {
        Self {
            clk: 0,
            registers: [0; 32],
            memory: BTreeMap::new(),
        }
    }

    // Option 1: ELF -> SuccinctELF -> Runtime

    // fn cpu_event(&mut self, instruction: &Instruction<i32>) {
    //     self.segment.cpu_events.push(CpuEvent {
    //         clk: self.clk,
    //         fp: self.fp,
    //         pc: self.pc,
    //         instruction: *instruction,
    //     });
    // }

    // fn read_word(&mut self, addr: usize) -> i32 {
    //     i32::from_le_bytes(
    //         self.memory[addr as usize..addr as usize + 4]
    //             .try_into()
    //             .unwrap(),
    //     )
    // }

    // fn write_word(&mut self, addr: usize, value: i32) {
    //     // TODO: can you write to uninitialized memory?
    //     self.memory[addr as usize..addr as usize + 4].copy_from_slice(&value.to_le_bytes());
    // }

    // fn alu_op(&mut self, op: Opcode, addr_d: usize, addr_1: usize, addr_2: usize) -> i32 {
    //     let v1 = self.read_word(addr_1);
    //     let v2 = self.read_word(addr_2);
    //     let result = match op {
    //         Opcode::ADD => v1 + v2,
    //         Opcode::AND => v1 | v2,
    //         Opcode::SLL => v1 << v2,
    //         _ => panic!("Invalid ALU opcode {}", op),
    //     };
    //     self.write_word(addr_d, result);
    //     self.segment.alu_events.push(AluEvent {
    //         clk: self.clk,
    //         opcode: op as u32,
    //         addr_d,
    //         addr_1,
    //         addr_2,
    //         v_d: result,
    //         v_1: v1,
    //         v_2: v2,
    //     });
    //     result
    // }

    // fn imm(&mut self, addr: usize, imm: i32) {
    //     self.write_word(addr, imm);
    // }

    // pub fn run(&mut self) -> Result<()> {
    //     // Iterate through the program, executing each instruction.
    //     let current_instruction = self.program.get_instruction(self.pc);
    //     let operands = current_instruction.operands.0;
    //     self.cpu_event(&current_instruction);

    //     match current_instruction.opcode {
    //         Opcode::ADD | Opcode::SUB | Opcode::XOR | Opcode::AND => {
    //             // Calculate address of each operand.
    //             let addr_d = self.fp + operands[0];
    //             let addr_1 = self.fp + operands[1];
    //             let addr_2 = self.fp + operands[2];

    //             self.alu_op(
    //                 current_instruction.opcode,
    //                 addr_d as usize,
    //                 addr_1 as usize,
    //                 addr_2 as usize,
    //             );
    //             self.pc += 1;
    //         }
    //         Opcode::IMM => {
    //             // Calculate address.
    //             let addr = (self.fp + operands[0]) as u32;
    //             let imm = operands[1];
    //             self.imm(addr as usize, imm);
    //         }
    //         _ => panic!("Invalid opcode {}", current_instruction.opcode),
    //     }

    //     self.clk += 1;
    //     Ok(())
    // }
}
