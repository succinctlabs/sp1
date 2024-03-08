use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use core::fmt;
use sp1_recursion_core::cpu::Instruction;
use sp1_recursion_core::runtime::Opcode;

use crate::builder::Builder;
use crate::ir::Felt;
use crate::util::canonical_i32_to_field;
use p3_field::PrimeField32;

#[derive(Debug, Clone)]
pub enum AsmInstruction<F> {
    /// Load work (src, dst) : load a value from the address stored at dest(fp) into src(fp).
    LW(i32, i32),
    /// Store word (src, dst) : store a value from src(fp) into the address stored at dest(fp).
    SW(i32, i32),
    // Get immediate (dst, value) : load a value into the dest(fp).
    IMM(i32, F),
    /// Add, dst = lhs + rhs.
    ADD(i32, i32, i32),
    /// Add immediate, dst = lhs + rhs.
    ADDI(i32, i32, F),
    /// Subtract, dst = lhs - rhs.
    SUB(i32, i32, i32),
    /// Subtract immediate, dst = lhs - rhs.
    SUBI(i32, i32, F),
    /// Subtract value from immediate, dst = rhs - lhs.
    SUBIN(i32, i32, F),
    /// Multiply, dst = lhs * rhs.
    MUL(i32, i32, i32),
    /// Multiply immediate.
    MULI(i32, i32, F),
    /// Divide, dst = lhs / rhs.
    DIV(i32, i32, i32),
    /// Divide immediate, dst = lhs / rhs.
    DIVI(i32, i32, F),
    /// Divide value from immediate, dst = rhs / lhs.
    DIVIN(i32, i32, F),
    /// Jump and link
    JAL(i32, F, F),
    /// Jump and link value
    JALR(i32, i32, i32),
    /// Branch not equal
    BNE(F, i32, i32),
    /// Branch not equal immediate
    BNEI(F, i32, F),
    /// Branch equal
    BEQ(F, i32, i32),
    /// Branch equal immediate
    BEQI(F, i32, F),
}

impl<F: PrimeField32> AsmInstruction<F> {
    pub fn j<B: Builder<F = F>>(label: F, builder: &mut B) -> Self {
        let dst = builder.uninit::<Felt<F>>();
        AsmInstruction::JAL(dst.0, label, F::zero())
    }

    pub fn machine_code(self, pc: usize, label_to_pc: &BTreeMap<usize, usize>) -> Instruction<F> {
        let i32_f = canonical_i32_to_field::<F>;
        let f_u32 = |x: F| x.as_canonical_u32();
        match self {
            AsmInstruction::LW(dst, src) => {
                Instruction::new(Opcode::LW, i32_f(dst), i32_f(src), 0, false, false)
            }
            AsmInstruction::SW(dst, src) => {
                Instruction::new(Opcode::SW, i32_f(dst), i32_f(src), 0, false, false)
            }
            AsmInstruction::IMM(dst, value) => {
                Instruction::new(Opcode::LW, i32_f(dst), f_u32(value), 0, true, false)
            }
            AsmInstruction::ADD(dst, lhs, rhs) => Instruction::new(
                Opcode::ADD,
                i32_f(dst),
                i32_f(lhs),
                i32_f(rhs),
                false,
                false,
            ),
            AsmInstruction::ADDI(dst, lhs, rhs) => {
                Instruction::new(Opcode::ADD, i32_f(dst), i32_f(lhs), f_u32(rhs), false, true)
            }
            AsmInstruction::SUB(dst, lhs, rhs) => Instruction::new(
                Opcode::SUB,
                i32_f(dst),
                i32_f(lhs),
                i32_f(rhs),
                false,
                false,
            ),
            AsmInstruction::SUBI(dst, lhs, rhs) => {
                Instruction::new(Opcode::SUB, i32_f(dst), i32_f(lhs), f_u32(rhs), false, true)
            }
            AsmInstruction::SUBIN(dst, lhs, rhs) => {
                Instruction::new(Opcode::SUB, i32_f(dst), f_u32(rhs), i32_f(lhs), true, false)
            }
            AsmInstruction::MUL(dst, lhs, rhs) => Instruction::new(
                Opcode::MUL,
                i32_f(dst),
                i32_f(lhs),
                i32_f(rhs),
                false,
                false,
            ),
            AsmInstruction::MULI(dst, lhs, rhs) => {
                Instruction::new(Opcode::MUL, i32_f(dst), i32_f(lhs), f_u32(rhs), false, true)
            }
            AsmInstruction::DIV(dst, lhs, rhs) => Instruction::new(
                Opcode::DIV,
                i32_f(dst),
                i32_f(lhs),
                i32_f(rhs),
                false,
                false,
            ),
            AsmInstruction::DIVI(dst, lhs, rhs) => {
                Instruction::new(Opcode::DIV, i32_f(dst), i32_f(lhs), f_u32(rhs), false, true)
            }
            AsmInstruction::DIVIN(dst, lhs, rhs) => {
                Instruction::new(Opcode::DIV, i32_f(dst), f_u32(rhs), i32_f(lhs), true, false)
            }
            // AsmInstruction::BEQ(label, lhs, rhs) => {
            //     let offset = label_to_pc[&label.as_canonical_u32()] as i32 - pc as i32;
            //     Instruction::new(Opcode::BEQ, i32_f(lhs), i32_f(rhs), offset, false, false)
            // }
            _ => todo!(),
        }
    }

    pub fn fmt(&self, labels: &BTreeMap<F, String>, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AsmInstruction::LW(dst, src) => write!(f, "lw ({})fp, ({})fp", dst, src),
            AsmInstruction::SW(dst, src) => write!(f, "sw ({})fp, ({})fp", dst, src),
            AsmInstruction::IMM(dst, value) => write!(f, "imm ({})fp, {}", dst, value),
            AsmInstruction::ADD(dst, lhs, rhs) => {
                write!(f, "add ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::ADDI(dst, lhs, rhs) => {
                write!(f, "addi ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::SUB(dst, lhs, rhs) => {
                write!(f, "sub ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::SUBI(dst, lhs, rhs) => {
                write!(f, "subi ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::SUBIN(dst, lhs, rhs) => {
                write!(f, "subin ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::MUL(dst, lhs, rhs) => {
                write!(f, "mul ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::MULI(dst, lhs, rhs) => {
                write!(f, "muli ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::DIV(dst, lhs, rhs) => {
                write!(f, "div ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::DIVI(dst, lhs, rhs) => {
                write!(f, "divi ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::DIVIN(dst, lhs, rhs) => {
                write!(f, "divin ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::JAL(dst, label, offset) => {
                if *offset == F::zero() {
                    return write!(
                        f,
                        "j ({})fp, {}",
                        dst,
                        labels.get(label).unwrap_or(&format!(".BBL_{}", label))
                    );
                }
                write!(
                    f,
                    "jal ({})fp, {}, {}",
                    dst,
                    labels.get(label).unwrap_or(&format!(".BBL_{}", label)),
                    offset
                )
            }
            AsmInstruction::JALR(dst, label, offset) => {
                write!(f, "jalr ({})fp, ({})fp, ({})fp", dst, label, offset)
            }
            AsmInstruction::BNE(label, lhs, rhs) => {
                write!(
                    f,
                    "bne {}, ({})fp, ({})fp",
                    labels.get(label).unwrap_or(&format!(".BBL_{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::BNEI(label, lhs, rhs) => {
                write!(
                    f,
                    "bnei .{}, ({})fp, {}",
                    labels.get(label).unwrap_or(&format!(".BBL_{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::BEQ(label, lhs, rhs) => {
                write!(
                    f,
                    "beq {}, ({})fp, ({})fp",
                    labels.get(label).unwrap_or(&format!(".BBL_{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::BEQI(label, lhs, rhs) => {
                write!(
                    f,
                    "beqi {}, ({})fp, {}",
                    labels.get(label).unwrap_or(&format!(".BBL_{}", label)),
                    lhs,
                    rhs
                )
            }
        }
    }
}
