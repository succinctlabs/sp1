use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

use super::MemoryRecordEnum;
use crate::events::PageProtRecord;
use crate::{vm::results::TrapResult, Instruction, Opcode};

/// Alu Instruction Event.
///
/// This object encapsulated the information needed to prove a RISC-V ALU operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, DeepSizeOf)]
#[repr(C)]
pub struct AluEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The program counter.
    pub pc: u64,
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand value.
    pub a: u64,
    /// The second operand value.
    pub b: u64,
    /// The third operand value.
    pub c: u64,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,
}

impl AluEvent {
    /// Create a new [`AluEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(clk: u64, pc: u64, opcode: Opcode, a: u64, b: u64, c: u64, op_a_0: bool) -> Self {
        Self { clk, pc, opcode, a, b, c, op_a_0 }
    }
}

/// Memory Instruction Event.
///
/// This object encapsulated the information needed to prove a RISC-V memory operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, DeepSizeOf)]
#[repr(C)]
pub struct MemInstrEvent {
    /// The clk.
    pub clk: u64,
    /// The program counter.
    pub pc: u64,
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand value.
    pub a: u64,
    /// The second operand value.
    pub b: u64,
    /// The third operand value.
    pub c: u64,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,
    /// The memory access record for memory operations.
    pub mem_access: MemoryRecordEnum,
}

impl MemInstrEvent {
    /// Create a new [`MemInstrEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clk: u64,
        pc: u64,
        opcode: Opcode,
        a: u64,
        b: u64,
        c: u64,
        op_a_0: bool,
        mem_access: MemoryRecordEnum,
    ) -> Self {
        Self { clk, pc, opcode, a, b, c, op_a_0, mem_access }
    }
}

/// Trap Memory Instruction Event.
///
/// This object encapsulated the information to prove a RISC-V memory operation that trapped.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, DeepSizeOf)]
#[repr(C)]
pub struct TrapMemInstrEvent {
    /// The clk.
    pub clk: u64,
    /// The program counter.
    pub pc: u64,
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand value.
    pub a: u64,
    /// The second operand value.
    pub b: u64,
    /// The third operand value.
    pub c: u64,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,
    /// The page permission record for memory operations.
    pub page_prot_access: PageProtRecord,
    /// The trap result.
    pub trap_result: TrapResult,
}

/// Branch Instruction Event.
///
/// This object encapsulated the information needed to prove a RISC-V branch operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, DeepSizeOf)]
#[repr(C)]
pub struct BranchEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The program counter.
    pub pc: u64,
    /// The next program counter.
    pub next_pc: u64,
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand value.
    pub a: u64,
    /// The second operand value.
    pub b: u64,
    /// The third operand value.
    pub c: u64,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,
}

impl BranchEvent {
    /// Create a new [`BranchEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clk: u64,
        pc: u64,
        next_pc: u64,
        opcode: Opcode,
        a: u64,
        b: u64,
        c: u64,
        op_a_0: bool,
    ) -> Self {
        Self { clk, pc, next_pc, opcode, a, b, c, op_a_0 }
    }
}

/// Jump Instruction Event.
///
/// This object encapsulated the information needed to prove a RISC-V jump operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, DeepSizeOf)]
#[repr(C)]
pub struct JumpEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The program counter.
    pub pc: u64,
    /// The next program counter.
    pub next_pc: u64,
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand value.
    pub a: u64,
    /// The second operand value.
    pub b: u64,
    /// The third operand value.
    pub c: u64,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,
}

impl JumpEvent {
    /// Create a new [`JumpEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clk: u64,
        pc: u64,
        next_pc: u64,
        opcode: Opcode,
        a: u64,
        b: u64,
        c: u64,
        op_a_0: bool,
    ) -> Self {
        Self { clk, pc, next_pc, opcode, a, b, c, op_a_0 }
    }
}
/// `UType` Instruction Event.
///
/// This object encapsulated the information needed to prove a RISC-V AUIPC and LUI operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, DeepSizeOf)]
#[repr(C)]
pub struct UTypeEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The program counter.
    pub pc: u64,
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand value.
    pub a: u64,
    /// The second operand value.
    pub b: u64,
    /// The third operand value.
    pub c: u64,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,
}

impl UTypeEvent {
    /// Create a new [`UTypeEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(clk: u64, pc: u64, opcode: Opcode, a: u64, b: u64, c: u64, op_a_0: bool) -> Self {
        Self { clk, pc, opcode, a, b, c, op_a_0 }
    }
}

/// A `TrapExec` Event.
///
/// The information needed to prove a trap on untrusted program's permissions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, DeepSizeOf)]
#[repr(C)]
pub struct TrapExecEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The program counter.
    pub pc: u64,
    /// The trap result.
    pub trap_result: TrapResult,
    /// The page permission record.
    pub page_prot_record: PageProtRecord,
}

/// Instruction Fetch Event.
///
/// This object encapsulated the information needed to prove an instruction fetch from memory.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, DeepSizeOf)]
#[repr(C)]
pub struct InstructionFetchEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The program counter.
    pub pc: u64,
    /// Decoded instruction.
    pub instruction: Instruction,
    /// Encoded instruction
    pub encoded_instruction: u32,
}

impl InstructionFetchEvent {
    /// Create a new [`InstructionFetchEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(clk: u64, pc: u64, instruction: Instruction, encoded_instruction: u32) -> Self {
        Self { clk, pc, instruction, encoded_instruction }
    }
}

/// Instruction Decode Event.
///
/// This object encapsulated the information needed to prove an instruction decode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, DeepSizeOf)]
#[repr(C)]
pub struct InstructionDecodeEvent {
    /// Decoded instruction.
    pub instruction: Instruction,
    /// Encoded instruction
    pub encoded_instruction: u32,
    /// The multiplicity of the instruction.
    pub multiplicity: usize,
}

impl InstructionDecodeEvent {
    /// Create a new [`InstructionDecodeEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(instruction: Instruction, encoded_instruction: u32, multiplicity: usize) -> Self {
        Self { instruction, encoded_instruction, multiplicity }
    }
}
