use crate::runtime::opcode::Opcode;
use crate::runtime::runtime::Register;
// An instruction specifies an operation to execute and the operands.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Instruction {
    pub opcode: Opcode,
    pub op_a: u32,
    pub op_b: u32,
    pub op_c: u32,
}

/// A runtime executes a program.
impl Instruction {
    /// Create a new instruction.
    pub fn new(opcode: Opcode, op_a: u32, op_b: u32, op_c: u32) -> Instruction {
        Instruction {
            opcode,
            op_a,
            op_b,
            op_c,
        }
    }

    /// Decode the instruction in the R-type format.
    pub fn r_type(&self) -> (Register, Register, Register) {
        (
            Register::from_u32(self.op_a),
            Register::from_u32(self.op_b),
            Register::from_u32(self.op_c),
        )
    }

    /// Decode the instruction in the I-type format.
    pub fn i_type(&self) -> (Register, Register, u32) {
        (
            Register::from_u32(self.op_a),
            Register::from_u32(self.op_b),
            self.op_c,
        )
    }

    /// Decode the instruction in the S-type format.
    pub fn s_type(&self) -> (Register, Register, u32) {
        (
            Register::from_u32(self.op_a),
            Register::from_u32(self.op_b),
            self.op_c,
        )
    }

    /// Decode the instruction in the B-type format.
    pub fn b_type(&self) -> (Register, Register, u32) {
        (
            Register::from_u32(self.op_a),
            Register::from_u32(self.op_b),
            self.op_c,
        )
    }

    /// Decode the instruction in the J-type format.
    pub fn j_type(&self) -> (Register, u32) {
        (Register::from_u32(self.op_a), self.op_b)
    }

    /// Decode the instruction in the U-type format.
    pub fn u_type(&self) -> (Register, u32) {
        (Register::from_u32(self.op_a), self.op_b)
    }

    /// Decode a binary representation of a RISC-V instruction and decode it.
    /// 
    /// Refer to P.104 of The RISC-V Instruction Set Manual for the exact
    /// specification.
    pub fn decode(input: u32) -> Self {
        // Check the constant instructions first.
        match input { 
            0xc0001073 => {
                // See https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#instruction-aliases
                return Instruction {
                    opcode: Opcode::UNIMP,
                    op_a: 0,
                    op_b: 0,
                    op_c: 0,
                };
            }
            0x73 => {
                // ECALL
                return Instruction {
                    opcode: Opcode::ECALL,
                    op_a: 0,
                    op_b: 0,
                    op_c: 0,
                };
            },
            0x00100073 => {
                // EBREAK
                return Instruction {
                    opcode: Opcode::EBREAK,
                    op_a: 0,
                    op_b: 0,
                    op_c: 0,
                };
            }
            _ => {
                // Remaining cases
            }
        }
        
        let op_code = input & 0b1111111;
        let rd = (input >> 7) & 0b11111;
        let funct3 = (input >> 12) & 0b111;
        let rs1 = (input >> 15) & 0b11111;
        let rs2 = (input >> 20) & 0b11111;
        let funct7 = (input >> 25) & 0b1111111;
        let imm_11_0 = (input >> 20) & 0b111111111111;
        let imm_11_5 = (input >> 25) & 0b1111111;
        let imm_4_0 = (input >> 7) & 0b11111;
        let imm_31_12 = (input >> 12) & 0xfffff; // 20-bit mask

        match op_code {
            0b0110111 => {
                // LUI
                Instruction {
                    opcode: Opcode::LUI,
                    op_a: rd,
                    op_b: imm_31_12,
                    op_c: 0,
                }
            }
            0b0010111 => {
                // AUIPC
                Instruction {
                    opcode: Opcode::AUIPC,
                    op_a: rd,
                    op_b: imm_31_12,
                    op_c: 0,
                }
            }
            0b1101111 => {
                // JAL
                let mut perm = Vec::<(usize, usize)>::new();
                perm.push((31, 20));
                for i in 1..11 {
                    perm.push((20 + i, i));
                }
                perm.push((20, 11));
                for i in 12..20 {
                    perm.push((i, i));
                }
                let mut imm = 0;
                for p in perm.iter() {
                    imm |= bit_op(input, p.0, p.1);
                }

                Instruction {
                    opcode: Opcode::JAL,
                    op_a: rd,
                    op_b: imm,
                    op_c: 0,
                }
            }
            0b1100111 => {
                // JALR
                Instruction {
                    opcode: Opcode::JALR,
                    op_a: rd,
                    op_b: (input >> 15) & 0b11111,
                    op_c: imm_11_0,
                }
            }
            0b1100011 => {
                // BEQ, BNE, BLT, BGE, BLTU, BGEU
                let opcode = match funct3 {
                    0b000 => Opcode::BEQ,
                    0b001 => Opcode::BNE,
                    0b100 => Opcode::BLT,
                    0b101 => Opcode::BGE,
                    0b110 => Opcode::BLTU,
                    0b111 => Opcode::BGEU,
                    _ => panic!("Invalid funct3 {}", funct3),
                };
                // Concatenate to form the immediate value
                let mut imm = bit_op(input, 31, 12);
                
                imm |= bit_op(input, 30, 10);
                imm |= bit_op(input, 29, 9);
                imm |= bit_op(input, 28, 8);
                imm |= bit_op(input, 27, 7);
                imm |= bit_op(input, 26, 6);
                imm |= bit_op(input, 25, 5);
                imm |= bit_op(input, 11, 4);
                imm |= bit_op(input, 10, 3);
                imm |= bit_op(input, 9, 2);
                imm |= bit_op(input, 8, 1);
                imm |= bit_op(input, 7, 11);

                Instruction {
                    opcode,
                    op_a: rs1,
                    op_b: rs2,
                    op_c: imm,
                }
            }
            0b0000011 => {
                // LB, LH, LW, LBU, LHU
                let opcode = match funct3 {
                    0b000 => Opcode::LB,
                    0b001 => Opcode::LH,
                    0b010 => Opcode::LW,
                    0b100 => Opcode::LBU,
                    0b101 => Opcode::LHU,
                    _ => panic!("Invalid funct3 {}", funct3),
                };
                Instruction {
                    opcode,
                    op_a: rd,
                    op_b: rs1,
                    op_c: imm_11_0,
                }
            }
            0b0100011 => {
                // SB, SH, SW
                let opcode = match funct3 {
                    0b000 => Opcode::SB,
                    0b001 => Opcode::SH,
                    0b010 => Opcode::SW,
                    _ => panic!("Invalid funct3 {}", funct3),
                };
                let imm = (imm_11_5 << 5) | imm_4_0;
                Instruction {
                    opcode,
                    op_a: rs2,
                    op_b: rs1,
                    op_c: imm,
                }
            }
            0b0010011 => {
                // ADDI, SLTI, SLTIU, XORI, ORI, ANDI, SLLI, SRLI, SRAI
                let opcode = match funct3 {
                    0b000 => Opcode::ADDI,
                    0b010 => Opcode::SLTI,
                    0b011 => Opcode::SLTIU,
                    0b100 => Opcode::XORI,
                    0b110 => Opcode::ORI,
                    0b111 => Opcode::ANDI,
                    0b001 => Opcode::SLLI,
                    0b101 => {
                        if funct7 == 0 {
                            Opcode::SRLI
                        } else if funct7 == 0b0100000 {
                            Opcode::SRAI
                        } else {
                            panic!("Invalid funct7 {}", funct7);
                        }
                    }
                    _ => panic!("Invalid funct3 {}", funct3),
                };
                if funct3 == 0b001 || funct3 == 0b101 {
                    Instruction {
                        opcode,
                        op_a: rd,
                        op_b: rs1,
                        op_c: (input >> 20) & 0b1111,
                    }
                } else {
                    Instruction {
                        opcode,
                        op_a: rd,
                        op_b: rs1,
                        op_c: extend_sign(imm_11_0, 12),
                    }
                }
            }
            0b0110011 => {
                // ADD, SUB, SLL, SLT, SLTU, XOR, SRL, SRA, OR, AND
                // M extension: MUL, MULH, MULHSU, MULHU, DIV, DIVU, REM, REMU
                let opcode = match (funct3, funct7) {

                    (0, 0) => Opcode::ADD,
                    (0, 0b0100000) => Opcode::SUB,
                    (0b001, 0) => Opcode::SLL,
                    (0b010, 0) => Opcode::SLT,
                    (0b011, 0) => Opcode::SLTU,
                    (0b100, 0) => Opcode::XOR,
                    (0b101, 0) => Opcode::SRL,
                    (0b101, 0b0100000) => Opcode::SRA,
                    (0b110, 0) => Opcode::OR,
                    (0b111, 0) => Opcode::AND,
                    (0, 1) => Opcode::MUL,
                    (0b001, 1) => Opcode::MULH,
                    (0b010, 1) => Opcode::MULHSU,
                    (0b011, 1) => Opcode::MULHU,
                    (0b100, 1) => Opcode::DIV,
                    (0b101, 1) => Opcode::DIVU,
                    (0b110, 1) => Opcode::REM,
                    (0b111, 1) => Opcode::REMU,
                    _ => panic!("Invalid input {:032b}", input),
                };
                Instruction {
                    opcode,
                    op_a: rd,
                    op_b: rs1,
                    op_c: rs2,
                }
            }
            0b0001111 => {
                // FENCE, FENCE.I
                let _opcode = match funct3 {
                    0b000 => panic!("FENCE not implemented"),
                    0b001 => panic!("FENCE.I not implemented"),
                    _ => panic!("Invalid instruction {}", input),
                };
            }
            0b1110011 => {
                panic!("CSRRW, CSRRS, CSRRC, CSRRWI, CSRRSI, CSRRCI not implemented 0x{:x}", input);
            }
            opcode => {
                todo!("opcode {} is invalid", opcode);
            }
        }
    }
}


/// Take the from-th bit of a and return a number whose to-th bit is set. The
/// least significant bit is the 0th bit.
fn bit_op(a: u32, from: usize, to: usize) -> u32{
    ((a >> from) & 1) << to
}

/// Treat the length-th bit as the sign bit and extend it all the way.
fn extend_sign(bits: u32, length : usize) -> u32 {
    if (bits >> (length - 1)) == 0 {
        bits
    } else {
        (0xffffffff << length) | bits
    }
}


#[cfg(test)]
#[allow(non_snake_case)]
pub mod tests {

    use crate::runtime::instruction::Instruction;

    use super::Opcode;
    fn decode_unit_test(input: u32, opcode: Opcode, rd: u32, rs1: u32, rs2: u32) {
        let exp = Instruction::new(opcode, rd, rs1, rs2);
        let got = Instruction::decode(input);
        assert_eq!(exp, got);
    }

    #[test]
    fn create_instruction_test() {
        decode_unit_test(0x00c58633, Opcode::ADD, 12, 11, 12);
        decode_unit_test(0x00d506b3, Opcode::ADD, 13, 10, 13);
        decode_unit_test(0x00a70533, Opcode::ADD, 10, 14, 10);
        decode_unit_test(0xffffe517, Opcode::AUIPC, 10,0xffffe, 0);
        decode_unit_test(0xfffff797, Opcode::AUIPC, 15,0xfffff, 0);

        decode_unit_test(0x00200793, Opcode::ADDI, 15,0,2);
        decode_unit_test(0x00000013, Opcode::ADDI, 0,0,0);
        decode_unit_test(0xfb010113, Opcode::ADDI, 2, 2, u32::MAX - 80 + 1); // addi sp, sp, -80
        decode_unit_test(0xc2958593, Opcode::ADDI, 11, 11, u32::MAX - 983 + 1); // addi a1, a1, -983

        decode_unit_test(0x05612c23, Opcode::SW, 22,2, 88); // sw x22,88(x2)
        decode_unit_test(0x01b12e23, Opcode::SW, 27,2, 28); // sw x27,28(x2)
        decode_unit_test(0x01052223, Opcode::SW, 16, 10, 4); // sw x16,4(x10)
        decode_unit_test(0x00a12423, Opcode::SW, 10, 2, 8); // sw	a0,8(sp)
        decode_unit_test(0x02052403, Opcode::LW, 8, 10, 32); // lw x8,32(x10)
        decode_unit_test(0x03452683, Opcode::LW, 13, 10, 52); // lw x13,52(x10)
        decode_unit_test(0x0006a703, Opcode::LW, 14,13, 0); // lw x14,0(x13)
        decode_unit_test(0x00001a37, Opcode::LUI,20,0x1, 0); // lui x20,0x1
        decode_unit_test(0x800002b7, Opcode::LUI,5,0x80000, 0); // lui x5,0x80000
        decode_unit_test(0x212120b7, Opcode::LUI,1,0x21212, 0); // lui x1,0x21212
        decode_unit_test(0x00e78023, Opcode::SB, 14, 15,0); // SB x14,0(x15)
        decode_unit_test(0x001101a3, Opcode::SB, 1,2, 3); // SB x1,3(x2)

        // TODO: do we want to support a negative offset?

        decode_unit_test(0x7e7218e3, Opcode::BNE, 4,7, 0xff0);
        decode_unit_test(0x5a231763, Opcode::BNE, 6,2,0x5ae);
        decode_unit_test(0x0eb51fe3, Opcode::BNE, 10,11,0x8fe);

        decode_unit_test(0x7e7268e3, Opcode::BLTU, 4,7, 0xff0);
        decode_unit_test(0x5a236763, Opcode::BLTU, 6,2,0x5ae);
        decode_unit_test(0x0eb56fe3, Opcode::BLTU, 10,11,0x8fe);

        decode_unit_test(0x0020bf33, Opcode::SLTU, 30,1,2);
        decode_unit_test(0x0020bf33, Opcode::SLTU, 30,1,2);
        decode_unit_test(0x000030b3, Opcode::SLTU, 1,0,0);

        decode_unit_test(0x0006c783, Opcode::LBU, 15,13, 0);
        decode_unit_test(0x0006c703, Opcode::LBU, 14,13, 0);
        decode_unit_test(0x0007c683, Opcode::LBU, 13,15, 0);

        // TODO: Do we want to support a negative offset?
        decode_unit_test(0x08077693,  Opcode::ANDI, 13,14,128);
        decode_unit_test(0x04077693,  Opcode::ANDI, 13,14,64);

        // TODO: negative offset?
        decode_unit_test(0x00111223, Opcode::SH, 1, 2, 4); // sh x1,4(x2)
        decode_unit_test(0x00111523, Opcode::SH, 1, 2, 10); // sh x1,10(x2)

        decode_unit_test(0x25c000ef, Opcode::JAL, 1, 604, 0); // jal x1 604
        decode_unit_test(0x72ff24ef, Opcode::JAL, 9, 0xf2f2e, 0); // jal x1 604
        decode_unit_test(0x2f22f36f, Opcode::JAL, 6, 0x2f2f2, 0); // jal x1 604

        decode_unit_test(0x00008067, Opcode::JALR, 0, 1, 0); // JALR x0 0(x1)
    }
}