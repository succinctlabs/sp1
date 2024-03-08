use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use core::fmt;

use crate::builder::Builder;
use crate::ir::Felt;
use p3_field::PrimeField;

#[derive(Debug, Clone)]
pub enum AsmInstruction<F> {
    /// Load work (src, dst) : load a value from the address stored at dest(fp) into src(fp).
    LW(i32, i32),
    /// Store word (src, dst) : store a value from src(fp) into the address stored at dest(fp).
    SW(i32, i32),
    // Get immediate (dst, value) : load a value into the dest(fp).
    IMM(i32, F),
    /// Add
    ADD(i32, i32, i32),
    /// Add immediate
    ADDI(i32, i32, F),
    /// Subtract
    SUB(i32, i32, i32),
    /// Subtract immediate
    SUBI(i32, i32, F),
    /// Subtract value from immediate, dst = lhs - rhs.
    SUBIN(i32, i32, F),
    /// Multiply
    MUL(i32, i32, i32),
    /// Multiply immediate.
    MULI(i32, i32, F),
    /// Divide
    DIV(i32, i32, i32),
    /// Divide immediate
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

impl<F: PrimeField> AsmInstruction<F> {
    pub fn j<B: Builder<F = F>>(label: F, builder: &mut B) -> Self {
        let dst = builder.uninit::<Felt<F>>();
        AsmInstruction::JAL(dst.0, label, F::zero())
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
