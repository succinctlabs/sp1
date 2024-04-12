use alloc::collections::BTreeMap;
use alloc::format;
use core::fmt;

use p3_field::{ExtensionField, PrimeField32};
use sp1_recursion_core::cpu::Instruction;
use sp1_recursion_core::runtime::Opcode;

use super::ZERO;
use crate::util::canonical_i32_to_field;

#[derive(Debug, Clone)]
pub enum AsmInstruction<F, EF> {
    /// Load word (dst, src, index, offset, size).
    ///
    /// Load a value from the address stored at src(fp) into dstfp).
    LoadF(i32, i32, i32, F, F),
    LoadFI(i32, i32, F, F, F),

    /// Store word (dst, src, index, offset, size)
    ///
    /// Store a value from src(fp) into the address stored at dest(fp).
    StoreF(i32, i32, i32, F, F),
    StoreFI(i32, i32, F, F, F),

    /// Get immediate (dst, value).
    ///
    /// Load a value into the dest(fp).
    ImmF(i32, F),

    /// Add, dst = lhs + rhs.
    AddF(i32, i32, i32),

    /// Add immediate, dst = lhs + rhs.
    AddFI(i32, i32, F),

    /// Subtract, dst = lhs - rhs.
    SubF(i32, i32, i32),

    /// Subtract immediate, dst = lhs - rhs.
    SubFI(i32, i32, F),

    /// Subtract value from immediate, dst = lhs - rhs.
    SubFIN(i32, F, i32),

    /// Multiply, dst = lhs * rhs.
    MulF(i32, i32, i32),

    /// Multiply immediate.
    MulFI(i32, i32, F),

    /// Divide, dst = lhs / rhs.
    DivF(i32, i32, i32),

    /// Divide immediate, dst = lhs / rhs.
    DivFI(i32, i32, F),

    /// Divide value from immediate, dst = lhs / rhs.
    DivFIN(i32, F, i32),

    /// Load an ext value (dst, src, index, offset, size).
    ///
    /// Load a value from the address stored at src(fp) into dst(fp).
    LoadE(i32, i32, i32, F, F),
    LoadEI(i32, i32, F, F, F),

    /// Store an ext value (dst, src, index, offset, size).
    ///
    /// Store a value from src(fp) into address stored at dst(fp).
    StoreE(i32, i32, i32, F, F),
    StoreEI(i32, i32, F, F, F),

    /// Get immediate extension value (dst, value).
    ///
    /// Load a value into the dest(fp).
    ImmE(i32, EF),

    /// Add extension, dst = lhs + rhs.
    AddE(i32, i32, i32),

    /// Add immediate extension, dst = lhs + rhs.
    AddEI(i32, i32, EF),

    /// Subtract extension, dst = lhs - rhs.
    SubE(i32, i32, i32),

    /// Subtract immediate extension, dst = lhs - rhs.
    SubEI(i32, i32, EF),

    /// Subtract value from immediate extension, dst = lhs - rhs.
    SubEIN(i32, EF, i32),

    /// Multiply extension, dst = lhs * rhs.
    MulE(i32, i32, i32),

    /// Multiply immediate extension.
    MulEI(i32, i32, EF),

    /// Divide extension, dst = lhs / rhs.
    DivE(i32, i32, i32),

    /// Divide immediate extension, dst = lhs / rhs.
    DivEI(i32, i32, EF),

    /// Divide value from immediate extension, dst = lhs / rhs.
    DivEIN(i32, EF, i32),

    /// Add base to extension, dst = lhs + rhs.
    AddEF(i32, i32, i32),

    /// Add immediate base to extension, dst = lhs + rhs.
    AddEFI(i32, i32, F),

    /// Add immediate extension element to base, dst = lhs + rhs.
    AddEIF(i32, i32, EF),

    // Subtract base from extension, dst = lhs - rhs.
    SubFE(i32, i32, i32),

    /// Subtract immediate base from extension, dst = lhs - rhs.
    SubFEI(i32, i32, F),

    /// Subtract value from immediate base to extension, dst = lhs - rhs.
    SubFEIN(i32, F, i32),

    /// Subtract extension from base, dst = lhs - rhs.
    SubEF(i32, i32, i32),

    /// Subtract immediate extension from base, dst = lhs - rhs.
    SubEIF(i32, i32, EF),

    /// Subtract value from immediate extension to base, dst = lhs - rhs.
    SubEIFN(i32, EF, i32),

    /// Multiply base and extension, dst = lhs * rhs.
    MulFE(i32, i32, i32),

    /// Multiply immediate base and extension.
    MulFIE(i32, i32, F),

    /// Multiply base by immediate extension, dst = lhs * rhs.
    MulEIF(i32, i32, EF),

    /// Divide base and extension, dst = lhs / rhs.
    DivFE(i32, i32, i32),

    /// Divide immediate base and extension, dst = lhs / rhs.
    DivFIE(i32, i32, F),

    /// Divide value from immediate base to extension, dst = lhs / rhs.
    DivFIEN(i32, F, i32),

    /// Divide extension from immediate base, dst = lhs / rhs.
    DivFEI(i32, i32, EF),

    /// Divide value from immediate extension to base, dst = lhs / rhs.
    DivEIF(i32, EF, i32),

    /// Jump and link.
    Jal(i32, F, F),

    /// Jump and link value.
    JalR(i32, i32, i32),

    /// Branch not equal.
    Bne(F, i32, i32),

    /// Branch not equal increment c by 1.
    BneInc(F, i32, i32),

    /// Branch not equal immediate.
    BneI(F, i32, F),

    /// Branch not equal immediate and increment c by 1.
    BneIInc(F, i32, F),

    /// Branch equal.
    Beq(F, i32, i32),

    /// Branch equal immediate.
    BeqI(F, i32, F),

    /// Branch not equal extension.
    BneE(F, i32, i32),

    /// Branch not equal immediate extension.
    BneEI(F, i32, EF),

    /// Branch equal extension.
    BeqE(F, i32, i32),

    /// Branch equal immediate extension.
    BeqEI(F, i32, EF),

    /// Trap.
    Trap,

    /// Break(label)
    Break(F),

    /// HintBits(dst, src).
    ///
    /// Decompose the field element `src` into bits and write them to the array
    /// starting at the address stored at `dst`.
    HintBits(i32, i32),

    /// Perform a permutation of the Poseidon2 hash function on the array specified by the ptr.
    Poseidon2Permute(i32, i32),
    Poseidon2Compress(i32, i32, i32),

    /// Print a variable.
    PrintV(i32),

    /// Print a felt.
    PrintF(i32),

    /// Print an extension element.
    PrintE(i32),

    /// Convert an extension element to field elements.
    Ext2Felt(i32, i32),

    /// Hint the lenght of the next vector of blocks.
    HintLen(i32),

    /// Hint a vector of blocks.
    Hint(i32),

    // FRIFold(m, input).
    FriFold(i32, i32),
    Commit(i32),

    LessThan(i32, i32, i32),
}

impl<F: PrimeField32, EF: ExtensionField<F>> AsmInstruction<F, EF> {
    pub fn j(label: F) -> Self {
        AsmInstruction::Jal(ZERO, label, F::zero())
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
            AsmInstruction::Break(_) => panic!("Unresolved break instruction"),
            AsmInstruction::LoadF(dst, src, index, offset, size) => Instruction::new(
                Opcode::LW,
                i32_f(dst),
                i32_f_arr(src),
                i32_f_arr(index),
                offset,
                size,
                false,
                false,
            ),
            AsmInstruction::LoadFI(dst, src, index, offset, size) => Instruction::new(
                Opcode::LW,
                i32_f(dst),
                i32_f_arr(src),
                f_u32(index),
                offset,
                size,
                false,
                true,
            ),
            AsmInstruction::StoreF(dst, src, index, offset, size) => Instruction::new(
                Opcode::SW,
                i32_f(dst),
                i32_f_arr(src),
                i32_f_arr(index),
                offset,
                size,
                false,
                false,
            ),
            AsmInstruction::StoreFI(dst, src, index, offset, size) => Instruction::new(
                Opcode::SW,
                i32_f(dst),
                i32_f_arr(src),
                f_u32(index),
                offset,
                size,
                false,
                true,
            ),

            AsmInstruction::ImmF(dst, value) => Instruction::new(
                Opcode::LW,
                i32_f(dst),
                f_u32(value),
                zero,
                F::zero(),
                F::one(),
                true,
                false,
            ),
            AsmInstruction::AddF(dst, lhs, rhs) => Instruction::new(
                Opcode::ADD,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::LessThan(dst, lhs, rhs) => Instruction::new(
                Opcode::LessThanF,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::AddFI(dst, lhs, rhs) => Instruction::new(
                Opcode::ADD,
                i32_f(dst),
                i32_f_arr(lhs),
                f_u32(rhs),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::SubF(dst, lhs, rhs) => Instruction::new(
                Opcode::SUB,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::SubFI(dst, lhs, rhs) => Instruction::new(
                Opcode::SUB,
                i32_f(dst),
                i32_f_arr(lhs),
                f_u32(rhs),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::SubFIN(dst, lhs, rhs) => Instruction::new(
                Opcode::SUB,
                i32_f(dst),
                f_u32(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                true,
                false,
            ),
            AsmInstruction::MulF(dst, lhs, rhs) => Instruction::new(
                Opcode::MUL,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::MulFI(dst, lhs, rhs) => Instruction::new(
                Opcode::MUL,
                i32_f(dst),
                i32_f_arr(lhs),
                f_u32(rhs),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::DivF(dst, lhs, rhs) => Instruction::new(
                Opcode::DIV,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::DivFI(dst, lhs, rhs) => Instruction::new(
                Opcode::DIV,
                i32_f(dst),
                i32_f_arr(lhs),
                f_u32(rhs),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::DivFIN(dst, lhs, rhs) => Instruction::new(
                Opcode::DIV,
                i32_f(dst),
                f_u32(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                true,
                false,
            ),
            AsmInstruction::LoadE(dst, src, index, offset, size) => Instruction::new(
                Opcode::LE,
                i32_f(dst),
                i32_f_arr(src),
                i32_f_arr(index),
                offset,
                size,
                false,
                false,
            ),
            AsmInstruction::LoadEI(dst, src, index, offset, size) => Instruction::new(
                Opcode::LE,
                i32_f(dst),
                i32_f_arr(src),
                f_u32(index),
                offset,
                size,
                false,
                true,
            ),
            AsmInstruction::StoreE(dst, src, index, offset, size) => Instruction::new(
                Opcode::SE,
                i32_f(dst),
                i32_f_arr(src),
                i32_f_arr(index),
                offset,
                size,
                false,
                false,
            ),
            AsmInstruction::StoreEI(dst, src, index, offset, size) => Instruction::new(
                Opcode::SE,
                i32_f(dst),
                i32_f_arr(src),
                f_u32(index),
                offset,
                size,
                false,
                true,
            ),
            AsmInstruction::ImmE(dst, value) => Instruction::new(
                Opcode::LE,
                i32_f(dst),
                value.as_base_slice().try_into().unwrap(),
                zero,
                F::zero(),
                F::zero(),
                true,
                false,
            ),
            AsmInstruction::AddE(dst, lhs, rhs) => Instruction::new(
                Opcode::EADD,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::AddEI(dst, lhs, rhs) => Instruction::new(
                Opcode::EADD,
                i32_f(dst),
                i32_f_arr(lhs),
                rhs.as_base_slice().try_into().unwrap(),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::SubE(dst, lhs, rhs) => Instruction::new(
                Opcode::ESUB,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::SubEI(dst, lhs, rhs) => Instruction::new(
                Opcode::ESUB,
                i32_f(dst),
                i32_f_arr(lhs),
                rhs.as_base_slice().try_into().unwrap(),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::SubEIN(dst, lhs, rhs) => Instruction::new(
                Opcode::ESUB,
                i32_f(dst),
                lhs.as_base_slice().try_into().unwrap(),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                true,
                false,
            ),
            AsmInstruction::MulE(dst, lhs, rhs) => Instruction::new(
                Opcode::EMUL,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::MulEI(dst, lhs, rhs) => Instruction::new(
                Opcode::EMUL,
                i32_f(dst),
                i32_f_arr(lhs),
                rhs.as_base_slice().try_into().unwrap(),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::DivE(dst, lhs, rhs) => Instruction::new(
                Opcode::EDIV,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::DivEI(dst, lhs, rhs) => Instruction::new(
                Opcode::EDIV,
                i32_f(dst),
                i32_f_arr(lhs),
                rhs.as_base_slice().try_into().unwrap(),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::DivEIN(dst, lhs, rhs) => Instruction::new(
                Opcode::EDIV,
                i32_f(dst),
                lhs.as_base_slice().try_into().unwrap(),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                true,
                false,
            ),
            AsmInstruction::AddEF(dst, lhs, rhs) => Instruction::new(
                Opcode::EFADD,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::AddEFI(dst, lhs, rhs) => Instruction::new(
                Opcode::EFADD,
                i32_f(dst),
                i32_f_arr(lhs),
                f_u32(rhs),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::AddEIF(dst, lhs, rhs) => Instruction::new(
                Opcode::EFADD,
                i32_f(dst),
                rhs.as_base_slice().try_into().unwrap(),
                i32_f_arr(lhs),
                F::zero(),
                F::zero(),
                true,
                false,
            ),
            AsmInstruction::SubFE(dst, lhs, rhs) => Instruction::new(
                Opcode::EFSUB,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::SubFEI(dst, lhs, rhs) => Instruction::new(
                Opcode::EFSUB,
                i32_f(dst),
                i32_f_arr(lhs),
                f_u32(rhs),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::SubFEIN(dst, lhs, rhs) => Instruction::new(
                Opcode::EFSUB,
                i32_f(dst),
                f_u32(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                true,
                false,
            ),
            AsmInstruction::SubEF(dst, lhs, rhs) => Instruction::new(
                Opcode::FESUB,
                i32_f(dst),
                i32_f_arr(rhs),
                i32_f_arr(lhs),
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::SubEIF(dst, lhs, rhs) => Instruction::new(
                Opcode::FESUB,
                i32_f(dst),
                i32_f_arr(lhs),
                rhs.as_base_slice().try_into().unwrap(),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::SubEIFN(dst, lhs, rhs) => Instruction::new(
                Opcode::FESUB,
                i32_f(dst),
                lhs.as_base_slice().try_into().unwrap(),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                true,
                false,
            ),
            AsmInstruction::MulFE(dst, lhs, rhs) => Instruction::new(
                Opcode::EFMUL,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::MulFIE(dst, lhs, rhs) => Instruction::new(
                Opcode::EFMUL,
                i32_f(dst),
                i32_f_arr(lhs),
                f_u32(rhs),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::MulEIF(dst, lhs, rhs) => Instruction::new(
                Opcode::EFMUL,
                i32_f(dst),
                i32_f_arr(lhs),
                rhs.as_base_slice().try_into().unwrap(),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::DivFE(dst, lhs, rhs) => Instruction::new(
                Opcode::EFDIV,
                i32_f(dst),
                i32_f_arr(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::DivFIE(dst, lhs, rhs) => Instruction::new(
                Opcode::EFDIV,
                i32_f(dst),
                i32_f_arr(lhs),
                f_u32(rhs),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::DivFIEN(dst, lhs, rhs) => Instruction::new(
                Opcode::FEDIV,
                i32_f(dst),
                f_u32(lhs),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                true,
                false,
            ),
            AsmInstruction::DivFEI(dst, lhs, rhs) => Instruction::new(
                Opcode::FEDIV,
                i32_f(dst),
                i32_f_arr(lhs),
                rhs.as_base_slice().try_into().unwrap(),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::DivEIF(dst, lhs, rhs) => Instruction::new(
                Opcode::EFDIV,
                i32_f(dst),
                lhs.as_base_slice().try_into().unwrap(),
                i32_f_arr(rhs),
                F::zero(),
                F::zero(),
                true,
                false,
            ),
            AsmInstruction::Beq(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::BEQ,
                    i32_f(lhs),
                    i32_f_arr(rhs),
                    f_u32(offset),
                    F::zero(),
                    F::zero(),
                    false,
                    true,
                )
            }
            AsmInstruction::BeqI(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::BEQ,
                    i32_f(lhs),
                    f_u32(rhs),
                    f_u32(offset),
                    F::zero(),
                    F::zero(),
                    true,
                    true,
                )
            }
            AsmInstruction::Bne(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::BNE,
                    i32_f(lhs),
                    i32_f_arr(rhs),
                    f_u32(offset),
                    F::zero(),
                    F::zero(),
                    false,
                    true,
                )
            }
            AsmInstruction::BneInc(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::BNEINC,
                    i32_f(lhs),
                    i32_f_arr(rhs),
                    f_u32(offset),
                    F::zero(),
                    F::zero(),
                    false,
                    true,
                )
            }
            AsmInstruction::BneI(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::BNE,
                    i32_f(lhs),
                    f_u32(rhs),
                    f_u32(offset),
                    F::zero(),
                    F::zero(),
                    true,
                    true,
                )
            }
            AsmInstruction::BneIInc(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::BNEINC,
                    i32_f(lhs),
                    f_u32(rhs),
                    f_u32(offset),
                    F::zero(),
                    F::zero(),
                    true,
                    true,
                )
            }
            AsmInstruction::BneE(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::EBNE,
                    i32_f(lhs),
                    i32_f_arr(rhs),
                    f_u32(offset),
                    F::zero(),
                    F::zero(),
                    false,
                    true,
                )
            }
            AsmInstruction::BneEI(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::EBNE,
                    i32_f(lhs),
                    rhs.as_base_slice().try_into().unwrap(),
                    f_u32(offset),
                    F::zero(),
                    F::zero(),
                    true,
                    true,
                )
            }
            AsmInstruction::BeqE(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::EBEQ,
                    i32_f(lhs),
                    i32_f_arr(rhs),
                    f_u32(offset),
                    F::zero(),
                    F::zero(),
                    false,
                    true,
                )
            }
            AsmInstruction::BeqEI(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::EBEQ,
                    i32_f(lhs),
                    rhs.as_base_slice().try_into().unwrap(),
                    f_u32(offset),
                    F::zero(),
                    F::zero(),
                    true,
                    true,
                )
            }
            AsmInstruction::Jal(dst, label, offset) => {
                let pc_offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::JAL,
                    i32_f(dst),
                    f_u32(pc_offset),
                    f_u32(offset),
                    F::zero(),
                    F::zero(),
                    false,
                    true,
                )
            }
            AsmInstruction::JalR(dst, label, offset) => Instruction::new(
                Opcode::JALR,
                i32_f(dst),
                i32_f_arr(label),
                i32_f_arr(offset),
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::Trap => Instruction::new(
                Opcode::TRAP,
                F::zero(),
                zero,
                zero,
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::HintBits(dst, src) => Instruction::new(
                Opcode::HintBits,
                i32_f(dst),
                i32_f_arr(src),
                f_u32(F::zero()),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::Poseidon2Permute(dst, src) => Instruction::new(
                Opcode::Poseidon2Perm,
                i32_f(dst),
                i32_f_arr(src),
                f_u32(F::zero()),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::PrintF(dst) => Instruction::new(
                Opcode::PrintF,
                i32_f(dst),
                f_u32(F::zero()),
                f_u32(F::zero()),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::PrintV(dst) => Instruction::new(
                Opcode::PrintF,
                i32_f(dst),
                f_u32(F::zero()),
                f_u32(F::zero()),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::PrintE(dst) => Instruction::new(
                Opcode::PrintE,
                i32_f(dst),
                f_u32(F::zero()),
                f_u32(F::zero()),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::Ext2Felt(dst, src) => Instruction::new(
                Opcode::Ext2Felt,
                i32_f(dst),
                i32_f_arr(src),
                f_u32(F::zero()),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::HintLen(dst) => Instruction::new(
                Opcode::HintLen,
                i32_f(dst),
                i32_f_arr(dst),
                f_u32(F::zero()),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::Hint(dst) => Instruction::new(
                Opcode::Hint,
                i32_f(dst),
                i32_f_arr(dst),
                f_u32(F::zero()),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::FriFold(m, ptr) => Instruction::new(
                Opcode::FRIFold,
                i32_f(m),
                i32_f_arr(ptr),
                f_u32(F::zero()),
                F::zero(),
                F::zero(),
                false,
                true,
            ),
            AsmInstruction::Poseidon2Compress(result, src1, src2) => Instruction::new(
                Opcode::Poseidon2Compress,
                i32_f(result),
                i32_f_arr(src1),
                i32_f_arr(src2),
                F::zero(),
                F::zero(),
                false,
                false,
            ),
            AsmInstruction::Commit(pv_hash) => Instruction::new(
                Opcode::Commit,
                i32_f(pv_hash),
                f_u32(F::zero()),
                f_u32(F::zero()),
                F::zero(),
                F::zero(),
                true,
                true,
            ),
        }
    }

    pub fn fmt(&self, labels: &BTreeMap<F, String>, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AsmInstruction::Break(_) => panic!("Unresolved break instruction"),
            AsmInstruction::LessThan(dst, left, right) => {
                write!(f, "lt  ({})fp, {}, {}", dst, left, right,)
            }
            AsmInstruction::LoadF(dst, src, index, offset, size) => {
                write!(
                    f,
                    "lw    ({})fp, ({})fp, ({})fp, {}, {}",
                    dst, src, index, offset, size
                )
            }
            AsmInstruction::LoadFI(dst, src, index, offset, size) => {
                write!(
                    f,
                    "lwi   ({})fp, ({})fp, {}, {}, {}",
                    dst, src, index, offset, size
                )
            }
            AsmInstruction::StoreF(dst, src, index, offset, size) => {
                write!(
                    f,
                    "sw    ({})fp, ({})fp, ({})fp, {}, {}",
                    dst, src, index, offset, size
                )
            }
            AsmInstruction::StoreFI(dst, src, index, offset, size) => {
                write!(
                    f,
                    "swi   ({})fp, ({})fp, {}, {}, {}",
                    dst, src, index, offset, size
                )
            }
            AsmInstruction::ImmF(dst, value) => write!(f, "imm   ({})fp, {}", dst, value),
            AsmInstruction::AddF(dst, lhs, rhs) => {
                write!(f, "add   ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::AddFI(dst, lhs, rhs) => {
                write!(f, "addi  ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::SubF(dst, lhs, rhs) => {
                write!(f, "sub   ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::SubFI(dst, lhs, rhs) => {
                write!(f, "subi  ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::SubFIN(dst, lhs, rhs) => {
                write!(f, "subin ({})fp, {}, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::MulF(dst, lhs, rhs) => {
                write!(f, "mul   ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::MulFI(dst, lhs, rhs) => {
                write!(f, "muli  ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::DivF(dst, lhs, rhs) => {
                write!(f, "div   ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::DivFI(dst, lhs, rhs) => {
                write!(f, "divi  ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::DivFIN(dst, lhs, rhs) => {
                write!(f, "divin ({})fp, {}, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::ImmE(dst, value) => write!(f, "eimm  ({})fp, {}", dst, value),
            AsmInstruction::LoadE(dst, src, index, offset, size) => {
                write!(
                    f,
                    "le    ({})fp, ({})fp, ({})fp, {}, {}",
                    dst, src, index, offset, size
                )
            }
            AsmInstruction::LoadEI(dst, src, index, offset, size) => {
                write!(
                    f,
                    "lei   ({})fp, ({})fp, {}, {}, {}",
                    dst, src, index, offset, size
                )
            }
            AsmInstruction::StoreE(dst, src, index, offset, size) => {
                write!(
                    f,
                    "se    ({})fp, ({})fp, ({})fp, {}, {}",
                    dst, src, index, offset, size
                )
            }
            AsmInstruction::StoreEI(dst, src, index, offset, size) => {
                write!(
                    f,
                    "sei   ({})fp, ({})fp, {}, {}, {}",
                    dst, src, index, offset, size
                )
            }
            AsmInstruction::AddE(dst, lhs, rhs) => {
                write!(f, "eadd  ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::AddEI(dst, lhs, rhs) => {
                write!(f, "eaddi ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::SubE(dst, lhs, rhs) => {
                write!(f, "esub  ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::SubEI(dst, lhs, rhs) => {
                write!(f, "esubi ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::SubEIN(dst, lhs, rhs) => {
                write!(f, "esubin ({})fp, {}, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::MulE(dst, lhs, rhs) => {
                write!(f, "emul  ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::MulEI(dst, lhs, rhs) => {
                write!(f, "emuli ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::DivE(dst, lhs, rhs) => {
                write!(f, "ediv  ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::DivEI(dst, lhs, rhs) => {
                write!(f, "edivi ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::DivEIN(dst, lhs, rhs) => {
                write!(f, "edivin ({})fp, {}, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::Jal(dst, label, offset) => {
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
            AsmInstruction::AddEF(dst, lhs, rhs) => {
                write!(f, "eaddf ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::AddEFI(dst, lhs, rhs) => {
                write!(f, "eaddfi ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::AddEIF(dst, lhs, rhs) => {
                write!(f, "faddei ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::SubFE(dst, lhs, rhs) => {
                write!(f, "esubf ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::SubFEI(dst, lhs, rhs) => {
                write!(f, "esubfi ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::SubFEIN(dst, lhs, rhs) => {
                write!(f, "esubfin ({})fp, {}, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::SubEF(dst, lhs, rhs) => {
                write!(f, "fsube ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::SubEIF(dst, lhs, rhs) => {
                write!(f, "fsubei ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::SubEIFN(dst, lhs, rhs) => {
                write!(f, "fsubein ({})fp, {}, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::MulFE(dst, lhs, rhs) => {
                write!(f, "emulf ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::MulFIE(dst, lhs, rhs) => {
                write!(f, "emulfi ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::MulEIF(dst, lhs, rhs) => {
                write!(f, "fmulei ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::DivFE(dst, lhs, rhs) => {
                write!(f, "edivf ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::DivFIE(dst, lhs, rhs) => {
                write!(f, "edivfi ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::DivFIEN(dst, lhs, rhs) => {
                write!(f, "edivfin ({})fp, {}, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::DivFEI(dst, lhs, rhs) => {
                write!(f, "fdivi ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            AsmInstruction::DivEIF(dst, lhs, rhs) => {
                write!(f, "fdivin ({})fp, {}, ({})fp", dst, lhs, rhs)
            }
            AsmInstruction::JalR(dst, label, offset) => {
                write!(f, "jalr  ({})fp, ({})fp, ({})fp", dst, label, offset)
            }
            AsmInstruction::Bne(label, lhs, rhs) => {
                write!(
                    f,
                    "bne   {}, ({})fp, ({})fp",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::BneI(label, lhs, rhs) => {
                write!(
                    f,
                    "bnei  {}, ({})fp, {}",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::BneInc(label, lhs, rhs) => {
                write!(
                    f,
                    "bneinc {}, ({})fp, {}",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::BneIInc(label, lhs, rhs) => {
                write!(
                    f,
                    "bneiinc {}, ({})fp, {}",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::Beq(label, lhs, rhs) => {
                write!(
                    f,
                    "beq  {}, ({})fp, ({})fp",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::BeqI(label, lhs, rhs) => {
                write!(
                    f,
                    "beqi {}, ({})fp, {}",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::BneE(label, lhs, rhs) => {
                write!(
                    f,
                    "ebne  {}, ({})fp, ({})fp",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::BneEI(label, lhs, rhs) => {
                write!(
                    f,
                    "ebnei {}, ({})fp, {}",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::BeqE(label, lhs, rhs) => {
                write!(
                    f,
                    "ebeq  {}, ({})fp, ({})fp",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::BeqEI(label, lhs, rhs) => {
                write!(
                    f,
                    "ebeqi {}, ({})fp, {}",
                    labels.get(label).unwrap_or(&format!(".L{}", label)),
                    lhs,
                    rhs
                )
            }
            AsmInstruction::Trap => write!(f, "trap"),
            AsmInstruction::HintBits(dst, src) => write!(f, "hint_bits ({})fp, ({})fp", dst, src),
            AsmInstruction::Poseidon2Permute(dst, src) => {
                write!(f, "poseidon2_permute ({})fp, ({})fp", dst, src)
            }
            AsmInstruction::PrintF(dst) => {
                write!(f, "print_f ({})fp", dst)
            }
            AsmInstruction::PrintV(dst) => {
                write!(f, "print_v ({})fp", dst)
            }
            AsmInstruction::PrintE(dst) => {
                write!(f, "print_e ({})fp", dst)
            }
            AsmInstruction::Ext2Felt(dst, src) => write!(f, "ext2felt ({})fp, {})fp", dst, src),
            AsmInstruction::HintLen(dst) => write!(f, "hint_len ({})fp", dst),
            AsmInstruction::Hint(dst) => write!(f, "hint ({})fp", dst),
            AsmInstruction::FriFold(m, input_ptr) => {
                write!(f, "fri_fold ({})fp, ({})fp", m, input_ptr)
            }
            AsmInstruction::Poseidon2Compress(result, src1, src2) => {
                write!(
                    f,
                    "poseidon2_compress ({})fp, {})fp, {})fp",
                    result, src1, src2
                )
            }
            AsmInstruction::Commit(pv_hash) => {
                write!(f, "commit ({})fp", pv_hash)
            }
        }
    }
}
