use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use core::fmt;
use sp1_recursion_core::cpu::Instruction;
use sp1_recursion_core::runtime::Opcode;

use crate::util::canonical_i32_to_field;
use p3_field::{ExtensionField, PrimeField32};

use super::ZERO;

#[derive(Debug, Clone)]
pub enum AsmInstruction<F, EF> {
    /// Load work (dst, src) : load a value from the address stored at src(fp) into dstfp).
    LW(i32, i32),
    /// Store word (dst, src) : store a value from src(fp) into the address stored at dest(fp).
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
    /// Subtract value from immediate, dst = lhs - rhs.
    SUBIN(i32, F, i32),
    /// Multiply, dst = lhs * rhs.
    MUL(i32, i32, i32),
    /// Multiply immediate.
    MULI(i32, i32, F),
    /// Divide, dst = lhs / rhs.
    DIV(i32, i32, i32),
    /// Divide immediate, dst = lhs / rhs.
    DIVI(i32, i32, F),
    /// Divide value from immediate, dst = lhs / rhs.
    DIVIN(i32, F, i32),

    // Extension operations
    /// Load an ext value (dst, src) : load a value from the address stored at src(fp) into dst(fp).
    LE(i32, i32),
    /// Store an ext value (dst, src) : store a value from src(fp) into address stored at dst(fp).
    SE(i32, i32),
    /// Get immediate extension value (dst, value) : load a value into the dest(fp).
    EIMM(i32, EF),
    /// Add extension, dst = lhs + rhs.
    EADD(i32, i32, i32),
    /// Add immediate extension, dst = lhs + rhs.
    EADDI(i32, i32, EF),
    /// Subtract extension, dst = lhs - rhs.
    ESUB(i32, i32, i32),
    /// Subtract immediate extension, dst = lhs - rhs.
    ESUBI(i32, i32, EF),
    /// Subtract value from immediate extension, dst = lhs - rhs.
    ESUBIN(i32, EF, i32),
    /// Multiply extension, dst = lhs * rhs.
    EMUL(i32, i32, i32),
    /// Multiply immediate extension.
    EMULI(i32, i32, EF),
    /// Divide extension, dst = lhs / rhs.
    EDIV(i32, i32, i32),
    /// Divide immediate extension, dst = lhs / rhs.
    EDIVI(i32, i32, EF),
    /// Divide value from immediate extension, dst = lhs / rhs.
    EDIVIN(i32, EF, i32),

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
    /// Branch not equal extension
    EBNE(F, i32, i32),
    /// Branch not equal immediate extension
    EBNEI(F, i32, EF),
    /// Branch equal extension
    EBEQ(F, i32, i32),
    /// Branch equal immediate extension
    EBEQI(F, i32, EF),

    // Custom Instructions
    /// Bit decompose the 32 least significant bits of the value in src and store the bits at the array
    /// starting at dst.
    NUM2BITS32(i32, i32),

    /// Trap
    TRAP,
}

impl<F: PrimeField32, EF: ExtensionField<F>> AsmInstruction<F, EF> {
    pub fn j(label: F) -> Self {
        AsmInstruction::JAL(ZERO, label, F::zero())
    }

    pub fn to_machine(self, pc: usize, label_to_pc: &BTreeMap<F, usize>) -> Instruction<F> {
        let i32_f = canonical_i32_to_field::<F>;
        let i32_f_arr = |x: i32| {
            [
                canonical_i32_to_field::<F>(x),
                F::zero(),
                F::zero(),
                F::zero(),
            ]
        };
        let f_u32 = |x: F| [x, F::zero(), F::zero(), F::zero()];
        let zero = [F::zero(), F::zero(), F::zero(), F::zero()];
        match self {
            AsmInstruction::LW(dst, src) => {
                Instruction::new(Opcode::LW, i32_f(dst), i32_f_arr(src), zero, false, false)
            }
            AsmInstruction::SW(dst, src) => {
                Instruction::new(Opcode::SW, i32_f(dst), i32_f_arr(src), zero, false, false)
            }
            AsmInstruction::IMM(dst, value) => {
                Instruction::new(Opcode::LW, i32_f(dst), f_u32(value), zero, true, false)
            }
            AsmInstruction::ADD(dst, lhs, rhs) => Instruction::new(
                Opcode::ADD,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                false,
                false,
            ),
            AsmInstruction::ADDI(dst, lhs, rhs) => Instruction::new(
                Opcode::ADD,
                i32_f(dst),
                i32_f_arr(lhs),
                f_u32(rhs),
                false,
                true,
            ),
            AsmInstruction::SUB(dst, lhs, rhs) => Instruction::new(
                Opcode::SUB,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                false,
                false,
            ),
            AsmInstruction::SUBI(dst, lhs, rhs) => Instruction::new(
                Opcode::SUB,
                i32_f(dst),
                i32_f_arr(lhs),
                f_u32(rhs),
                false,
                true,
            ),
            AsmInstruction::SUBIN(dst, lhs, rhs) => Instruction::new(
                Opcode::SUB,
                i32_f(dst),
                f_u32(lhs),
                i32_f_arr(rhs),
                true,
                false,
            ),
            AsmInstruction::MUL(dst, lhs, rhs) => Instruction::new(
                Opcode::MUL,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                false,
                false,
            ),
            AsmInstruction::MULI(dst, lhs, rhs) => Instruction::new(
                Opcode::MUL,
                i32_f(dst),
                i32_f_arr(lhs),
                f_u32(rhs),
                false,
                true,
            ),
            AsmInstruction::DIV(dst, lhs, rhs) => Instruction::new(
                Opcode::DIV,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                false,
                false,
            ),
            AsmInstruction::DIVI(dst, lhs, rhs) => Instruction::new(
                Opcode::DIV,
                i32_f(dst),
                i32_f_arr(lhs),
                f_u32(rhs),
                false,
                true,
            ),
            AsmInstruction::DIVIN(dst, lhs, rhs) => Instruction::new(
                Opcode::DIV,
                i32_f(dst),
                f_u32(lhs),
                i32_f_arr(rhs),
                true,
                false,
            ),
            AsmInstruction::LE(dst, src) => {
                Instruction::new(Opcode::LE, i32_f(dst), i32_f_arr(src), zero, false, false)
            }
            AsmInstruction::SE(dst, src) => {
                Instruction::new(Opcode::SE, i32_f(dst), i32_f_arr(src), zero, false, false)
            }
            AsmInstruction::EIMM(dst, value) => Instruction::new(
                Opcode::LE,
                i32_f(dst),
                value.as_base_slice().try_into().unwrap(),
                zero,
                true,
                false,
            ),
            AsmInstruction::EADD(dst, lhs, rhs) => Instruction::new(
                Opcode::EADD,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                false,
                false,
            ),
            AsmInstruction::EADDI(dst, lhs, rhs) => Instruction::new(
                Opcode::EADD,
                i32_f(dst),
                i32_f_arr(lhs),
                rhs.as_base_slice().try_into().unwrap(),
                false,
                true,
            ),
            AsmInstruction::ESUB(dst, lhs, rhs) => Instruction::new(
                Opcode::ESUB,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                false,
                false,
            ),
            AsmInstruction::ESUBI(dst, lhs, rhs) => Instruction::new(
                Opcode::ESUB,
                i32_f(dst),
                i32_f_arr(lhs),
                rhs.as_base_slice().try_into().unwrap(),
                false,
                true,
            ),
            AsmInstruction::ESUBIN(dst, lhs, rhs) => Instruction::new(
                Opcode::ESUB,
                i32_f(dst),
                lhs.as_base_slice().try_into().unwrap(),
                i32_f_arr(rhs),
                true,
                false,
            ),
            AsmInstruction::EMUL(dst, lhs, rhs) => Instruction::new(
                Opcode::EMUL,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                false,
                false,
            ),
            AsmInstruction::EMULI(dst, lhs, rhs) => Instruction::new(
                Opcode::EMUL,
                i32_f(dst),
                i32_f_arr(lhs),
                rhs.as_base_slice().try_into().unwrap(),
                false,
                true,
            ),
            AsmInstruction::EDIV(dst, lhs, rhs) => Instruction::new(
                Opcode::EDIV,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                false,
                false,
            ),
            AsmInstruction::EDIVI(dst, lhs, rhs) => Instruction::new(
                Opcode::EDIV,
                i32_f(dst),
                i32_f_arr(lhs),
                rhs.as_base_slice().try_into().unwrap(),
                false,
                true,
            ),
            AsmInstruction::EDIVIN(dst, lhs, rhs) => Instruction::new(
                Opcode::EDIV,
                i32_f(dst),
                lhs.as_base_slice().try_into().unwrap(),
                i32_f_arr(rhs),
                true,
                false,
            ),
            AsmInstruction::BEQ(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::BEQ,
                    i32_f(lhs),
                    i32_f_arr(rhs),
                    f_u32(offset),
                    false,
                    true,
                )
            }
            AsmInstruction::BEQI(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::BEQ,
                    i32_f(lhs),
                    f_u32(rhs),
                    f_u32(offset),
                    true,
                    true,
                )
            }
            AsmInstruction::BNE(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::BNE,
                    i32_f(lhs),
                    i32_f_arr(rhs),
                    f_u32(offset),
                    false,
                    true,
                )
            }
            AsmInstruction::BNEI(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::BNE,
                    i32_f(lhs),
                    f_u32(rhs),
                    f_u32(offset),
                    true,
                    true,
                )
            }
            AsmInstruction::EBNE(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::EBNE,
                    i32_f(lhs),
                    i32_f_arr(rhs),
                    f_u32(offset),
                    false,
                    true,
                )
            }
            AsmInstruction::EBNEI(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::EBNE,
                    i32_f(lhs),
                    rhs.as_base_slice().try_into().unwrap(),
                    f_u32(offset),
                    true,
                    true,
                )
            }
            AsmInstruction::EBEQ(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::EBEQ,
                    i32_f(lhs),
                    i32_f_arr(rhs),
                    f_u32(offset),
                    false,
                    true,
                )
            }
            AsmInstruction::EBEQI(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::EBEQ,
                    i32_f(lhs),
                    rhs.as_base_slice().try_into().unwrap(),
                    f_u32(offset),
                    true,
                    true,
                )
            }
            AsmInstruction::JAL(dst, label, offset) => {
                let pc_offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::JAL,
                    i32_f(dst),
                    f_u32(pc_offset),
                    f_u32(offset),
                    false,
                    true,
                )
            }
            AsmInstruction::JALR(dst, label, offset) => Instruction::new(
                Opcode::JALR,
                i32_f(dst),
                i32_f_arr(label),
                i32_f_arr(offset),
                false,
                false,
            ),
            AsmInstruction::NUM2BITS32(dst, input) => Instruction::new(
                Opcode::NUM2BITS32,
                i32_f(dst),
                i32_f_arr(input),
                zero,
                false,
                false,
            ),
            AsmInstruction::TRAP => {
                Instruction::new(Opcode::TRAP, F::zero(), zero, zero, false, false)
            }
        }
    }

    pub fn fmt(&self, labels: &BTreeMap<F, String>, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AsmInstruction::LW(dst, src) => write!(f, "lw    ({})fp, ({})fp", dst, src),
            AsmInstruction::SW(dst, src) => write!(f, "sw    ({})fp, ({})fp", dst, src),
            AsmInstruction::IMM(dst, value) => write!(f, "imm   ({})fp, {}", dst, value),
            AsmInstruction::ADD(dst, lhs, rhs) => {
                write!(f, "add   ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::ADDI(dst, lhs, rhs) => {
                write!(f, "addi  ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::SUB(dst, lhs, rhs) => {
                write!(f, "sub   ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::SUBI(dst, lhs, rhs) => {
                write!(f, "subi  ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::SUBIN(dst, lhs, rhs) => {
                write!(f, "subin ({})fp, {}, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::MUL(dst, lhs, rhs) => {
                write!(f, "mul   ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::MULI(dst, lhs, rhs) => {
                write!(f, "muli  ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::DIV(dst, lhs, rhs) => {
                write!(f, "div   ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::DIVI(dst, lhs, rhs) => {
                write!(f, "divi  ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::DIVIN(dst, lhs, rhs) => {
                write!(f, "divin ({})fp, {}, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::EIMM(dst, value) => write!(f, "eimm  ({})fp, {}", dst, value),
            AsmInstruction::LE(dst, src) => write!(f, "le    ({})fp, ({})fp", dst, src),
            AsmInstruction::SE(dst, src) => write!(f, "se    ({})fp, ({})fp", dst, src),
            AsmInstruction::EADD(dst, lhs, rhs) => {
                write!(f, "eadd  ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::EADDI(dst, lhs, rhs) => {
                write!(f, "eaddi ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::ESUB(dst, lhs, rhs) => {
                write!(f, "esub  ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::ESUBI(dst, lhs, rhs) => {
                write!(f, "esubi ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::ESUBIN(dst, lhs, rhs) => {
                write!(f, "esubin ({})fp, {}, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::EMUL(dst, lhs, rhs) => {
                write!(f, "emul  ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::EMULI(dst, lhs, rhs) => {
                write!(f, "emuli ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::EDIV(dst, lhs, rhs) => {
                write!(f, "ediv  ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::EDIVI(dst, lhs, rhs) => {
                write!(f, "edivi ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::EDIVIN(dst, lhs, rhs) => {
                write!(f, "edivin ({})fp, {}, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::JAL(dst, label, offset) => {
                if *offset == F::zero() {
                    return write!(
                        f,
                        "j     ({})fp, {}",
                        dst,
                        labels.get(label).unwrap_or(&format!(".L{}", label))
                    );
                }
                write!(
                    f,
                    "jal   ({})fp, {}, {}",
                    dst,
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    offset
                )
            }
            AsmInstruction::JALR(dst, label, offset) => {
                write!(f, "jalr  ({})fp, ({})fp, ({})fp", dst, label, offset)
            }
            AsmInstruction::BNE(label, lhs, rhs) => {
                write!(
                    f,
                    "bne   {}, ({})fp, ({})fp",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::BNEI(label, lhs, rhs) => {
                write!(
                    f,
                    "bnei  {}, ({})fp, {}",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::BEQ(label, lhs, rhs) => {
                write!(
                    f,
                    "beq  {}, ({})fp, ({})fp",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::BEQI(label, lhs, rhs) => {
                write!(
                    f,
                    "beqi {}, ({})fp, {}",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::EBNE(label, lhs, rhs) => {
                write!(
                    f,
                    "ebne  {}, ({})fp, ({})fp",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::EBNEI(label, lhs, rhs) => {
                write!(
                    f,
                    "ebnei {}, ({})fp, {}",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::EBEQ(label, lhs, rhs) => {
                write!(
                    f,
                    "ebeq  {}, ({})fp, ({})fp",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::EBEQI(label, lhs, rhs) => {
                write!(
                    f,
                    "ebeqi {}, ({})fp, {}",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::NUM2BITS32(dst, input) => {
                write!(f, "num2bits32 ({})fp, ({})fp", dst, input)
            }
            AsmInstruction::TRAP => write!(f, "trap"),
        }
    }
}
