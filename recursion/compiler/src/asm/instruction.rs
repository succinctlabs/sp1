use alloc::collections::BTreeMap;
use alloc::format;
use core::fmt;

use p3_field::{ExtensionField, PrimeField32};
use sp1_recursion_core::cpu::Instruction;
use sp1_recursion_core::runtime::{Opcode, PERMUTATION_WIDTH};

use super::A0;
use crate::util::canonical_i32_to_field;

#[derive(Debug, Clone)]
pub enum AsmInstruction<F, EF> {
    /// Load word (dst, src, index, offset, size).
    ///
    /// Load a value from the address stored at src(fp) into dstfp).
    LoadF(i32, i32, i32, F, F),
    LoadFI(i32, i32, F, F, F),

    /// Store word (val, addr, index, offset, size)
    ///
    /// Store a value from val(fp) into the address stored at addr(fp) with given index and offset.
    StoreF(i32, i32, i32, F, F),
    StoreFI(i32, i32, F, F, F),

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

    /// Store an ext value (val, addr, index, offset, size).
    ///
    /// Store a value from val(fp) into the address stored at addr(fp) with given index and offset.
    StoreE(i32, i32, i32, F, F),
    StoreEI(i32, i32, F, F, F),

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

    /// Halt.
    Halt,

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

    // Commit(val, index).
    Commit(i32, i32),

    // RegisterPublicValue(val).
    RegisterPublicValue(i32),

    LessThan(i32, i32, i32),

    CycleTracker(String),
}

impl<F: PrimeField32, EF: ExtensionField<F>> AsmInstruction<F, EF> {
    pub fn j(label: F) -> Self {
        AsmInstruction::Jal(A0, label, F::zero())
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
                Opcode::LOAD,
                i32_f(dst),
                i32_f_arr(src),
                i32_f_arr(index),
                offset,
                size,
                false,
                false,
                "".to_string(),
            ),
            AsmInstruction::LoadFI(dst, src, index, offset, size) => Instruction::new(
                Opcode::LOAD,
                i32_f(dst),
                i32_f_arr(src),
                f_u32(index),
                offset,
                size,
                false,
                true,
                "".to_string(),
            ),
            AsmInstruction::StoreF(value, addr, index, offset, size) => Instruction::new(
                Opcode::STORE,
                i32_f(value),
                i32_f_arr(addr),
                i32_f_arr(index),
                offset,
                size,
                false,
                false,
                "".to_string(),
            ),
            AsmInstruction::StoreFI(value, addr, index, offset, size) => Instruction::new(
                Opcode::STORE,
                i32_f(value),
                i32_f_arr(addr),
                f_u32(index),
                offset,
                size,
                false,
                true,
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
            ),
            AsmInstruction::LoadE(dst, src, index, offset, size) => Instruction::new(
                Opcode::LOAD,
                i32_f(dst),
                i32_f_arr(src),
                i32_f_arr(index),
                offset,
                size,
                false,
                false,
                "".to_string(),
            ),
            AsmInstruction::LoadEI(dst, src, index, offset, size) => Instruction::new(
                Opcode::LOAD,
                i32_f(dst),
                i32_f_arr(src),
                f_u32(index),
                offset,
                size,
                false,
                true,
                "".to_string(),
            ),
            AsmInstruction::StoreE(value, addr, index, offset, size) => Instruction::new(
                Opcode::STORE,
                i32_f(value),
                i32_f_arr(addr),
                i32_f_arr(index),
                offset,
                size,
                false,
                false,
                "".to_string(),
            ),
            AsmInstruction::StoreEI(value, addr, index, offset, size) => Instruction::new(
                Opcode::STORE,
                i32_f(value),
                i32_f_arr(addr),
                f_u32(index),
                offset,
                size,
                false,
                true,
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                    "".to_string(),
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
                    "".to_string(),
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
                    "".to_string(),
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
                    "".to_string(),
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
                    "".to_string(),
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
                    "".to_string(),
                )
            }
            AsmInstruction::BneE(label, lhs, rhs) => {
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
                    "".to_string(),
                )
            }
            AsmInstruction::BneEI(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::BNE,
                    i32_f(lhs),
                    rhs.as_base_slice().try_into().unwrap(),
                    f_u32(offset),
                    F::zero(),
                    F::zero(),
                    true,
                    true,
                    "".to_string(),
                )
            }
            AsmInstruction::BeqE(label, lhs, rhs) => {
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
                    "".to_string(),
                )
            }
            AsmInstruction::BeqEI(label, lhs, rhs) => {
                let offset =
                    F::from_canonical_usize(label_to_pc[&label]) - F::from_canonical_usize(pc);
                Instruction::new(
                    Opcode::BEQ,
                    i32_f(lhs),
                    rhs.as_base_slice().try_into().unwrap(),
                    f_u32(offset),
                    F::zero(),
                    F::zero(),
                    true,
                    true,
                    "".to_string(),
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
                    true,
                    true,
                    "".to_string(),
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
                true,
                "".to_string(),
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
                "".to_string(),
            ),
            AsmInstruction::Halt => Instruction::new(
                Opcode::HALT,
                F::zero(),
                zero,
                zero,
                F::zero(),
                F::zero(),
                false,
                false,
                "".to_string(),
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
                "".to_string(),
            ),
            AsmInstruction::Poseidon2Permute(dst, src) => Instruction::new(
                Opcode::Poseidon2Compress,
                i32_f(dst),
                i32_f_arr(src),
                i32_f_arr(src),
                F::from_canonical_usize(PERMUTATION_WIDTH / 2),
                F::zero(),
                false,
                false,
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
            ),
            AsmInstruction::CycleTracker(name) => Instruction::new(
                Opcode::CycleTracker,
                i32_f(0),
                f_u32(F::zero()),
                f_u32(F::zero()),
                F::zero(),
                F::zero(),
                true,
                false,
                name,
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
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
                "".to_string(),
            ),
            AsmInstruction::Commit(val, index) => Instruction::new(
                Opcode::Commit,
                i32_f(val),
                i32_f_arr(index),
                f_u32(F::zero()),
                F::zero(),
                F::zero(),
                false,
                true,
                "".to_string(),
            ),
            AsmInstruction::RegisterPublicValue(val) => Instruction::new(
                Opcode::RegisterPublicValue,
                i32_f(val),
                f_u32(F::zero()),
                f_u32(F::zero()),
                F::zero(),
                F::zero(),
                false,
                true,
                "".to_string(),
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
            AsmInstruction::Halt => write!(f, "halt"),
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
            AsmInstruction::Commit(val, index) => {
                write!(f, "commit ({})fp ({})fp", val, index)
            }
            AsmInstruction::RegisterPublicValue(val) => {
                write!(f, "register_public_value ({})fp", val)
            }
            AsmInstruction::CycleTracker(name) => {
                write!(f, "cycle-tracker {}", name)
            }
        }
    }
}
