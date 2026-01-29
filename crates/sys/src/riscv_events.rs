//! GPU-compatible event structures for RISC-V chips.
//!
//! These structures flatten the complex Rust event types (which contain Options,
//! enums, etc.) into simple C-compatible structs that can be passed to CUDA kernels.

/// A memory access record flattened for GPU use.
///
/// This captures the essential data from `MemoryRecordEnum`:
/// - prev_value: The previous value at this memory location
/// - prev_timestamp: The timestamp of the previous access
/// - current_timestamp: The timestamp of this access
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct GpuMemoryAccess {
    /// The previous value at this memory location (u64 stored as 4 u16 limbs would be more
    /// efficient, but we keep u64 for simplicity).
    pub prev_value: u64,
    /// The timestamp of the previous access.
    pub prev_timestamp: u64,
    /// The timestamp of this access.
    pub current_timestamp: u64,
}

/// GPU-compatible event for AddChip.
///
/// This flattens `AluEvent` and `RTypeRecord` into a single struct without Options or enums.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct AddGpuEvent {
    // From AluEvent
    /// Clock cycle of this instruction.
    pub clk: u64,
    /// Program counter of this instruction.
    pub pc: u64,
    /// First operand value (from rs1).
    pub b: u64,
    /// Second operand value (from rs2).
    pub c: u64,

    // From RTypeRecord
    /// Destination register number (rd).
    pub op_a: u8,
    /// Source register 1 spec (rs1).
    pub op_b: u64,
    /// Source register 2 spec (rs2).
    pub op_c: u64,

    /// Memory access record for destination register (write).
    pub mem_a: GpuMemoryAccess,
    /// Memory access record for source register 1 (read).
    pub mem_b: GpuMemoryAccess,
    /// Memory access record for source register 2 (read).
    pub mem_c: GpuMemoryAccess,
}

/// GPU-compatible event for AddwChip.
///
/// This flattens `AluEvent` and `ALUTypeRecord` into a single struct without Options or enums.
/// ALUTypeRecord differs from RTypeRecord in that op_c can be an immediate value.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct AddwGpuEvent {
    // From AluEvent
    /// Clock cycle of this instruction.
    pub clk: u64,
    /// Program counter of this instruction.
    pub pc: u64,
    /// First operand value (from rs1).
    pub b: u64,
    /// Second operand value (from rs2 or immediate).
    pub c: u64,

    // From ALUTypeRecord
    /// Destination register number (rd).
    pub op_a: u8,
    /// Source register 1 spec (rs1).
    pub op_b: u64,
    /// Source register 2 or immediate value (op_c stored as Word<T> which is 4 limbs of u16).
    pub op_c: u64,
    /// Whether op_c is an immediate value.
    pub is_imm: bool,

    /// Memory access record for destination register (write).
    pub mem_a: GpuMemoryAccess,
    /// Memory access record for source register 1 (read).
    pub mem_b: GpuMemoryAccess,
    /// Memory access record for source register 2 (read). Only valid if !is_imm.
    pub mem_c: GpuMemoryAccess,
}

/// GPU-compatible event for SubChip.
///
/// This flattens `AluEvent` and `RTypeRecord` into a single struct without Options or enums.
/// SubChip is structurally identical to AddChip - both use R-type instruction format.
pub type SubGpuEvent = AddGpuEvent;

/// GPU-compatible event for SubwChip.
///
/// This flattens `AluEvent` and `RTypeRecord` into a single struct without Options or enums.
/// SubwChip uses R-type instruction format (same as SubChip and AddChip).
pub type SubwGpuEvent = AddGpuEvent;

/// GPU-compatible event for AddiChip.
///
/// This flattens `AluEvent` and `ITypeRecord` into a single struct without Options or enums.
/// ITypeRecord uses I-type instruction format where op_c is always an immediate value.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct AddiGpuEvent {
    // From AluEvent
    /// Clock cycle of this instruction.
    pub clk: u64,
    /// Program counter of this instruction.
    pub pc: u64,
    /// First operand value (from rs1).
    pub b: u64,
    /// Second operand value (immediate).
    pub c: u64,

    // From ITypeRecord
    /// Destination register number (rd).
    pub op_a: u8,
    /// Source register 1 spec (rs1).
    pub op_b: u64,
    /// Immediate value (op_c).
    pub op_c: u64,

    /// Memory access record for destination register (write).
    pub mem_a: GpuMemoryAccess,
    /// Memory access record for source register 1 (read).
    pub mem_b: GpuMemoryAccess,
}

/// GPU-compatible event for MulChip.
///
/// This flattens `AluEvent` and `RTypeRecord` into a single struct without Options or enums.
/// MulChip uses R-type instruction format (same as AddChip, SubChip).
/// It also needs the opcode to distinguish between MUL, MULH, MULHU, MULHSU, MULW.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct MulGpuEvent {
    // From AluEvent
    /// Clock cycle of this instruction.
    pub clk: u64,
    /// Program counter of this instruction.
    pub pc: u64,
    /// First operand value (from rs1).
    pub b: u64,
    /// Second operand value (from rs2).
    pub c: u64,
    /// Result value.
    pub a: u64,
    /// Opcode value to distinguish MUL variants (MUL=0, MULH=1, MULHU=2, MULHSU=3, MULW=4).
    pub opcode: u8,

    // From RTypeRecord
    /// Destination register number (rd).
    pub op_a: u8,
    /// Source register 1 spec (rs1).
    pub op_b: u64,
    /// Source register 2 spec (rs2).
    pub op_c: u64,

    /// Memory access record for destination register (write).
    pub mem_a: GpuMemoryAccess,
    /// Memory access record for source register 1 (read).
    pub mem_b: GpuMemoryAccess,
    /// Memory access record for source register 2 (read).
    pub mem_c: GpuMemoryAccess,
}

/// GPU-compatible event for LtChip (SLT, SLTU, SLTI, SLTIU).
///
/// This flattens `AluEvent` and `ALUTypeRecord` into a single struct without Options or enums.
/// LtChip uses ALUTypeReader (same as AddwChip) since it supports both register and immediate modes.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct LtGpuEvent {
    // From AluEvent
    /// Clock cycle of this instruction.
    pub clk: u64,
    /// Program counter of this instruction.
    pub pc: u64,
    /// First operand value (from rs1).
    pub b: u64,
    /// Second operand value (from rs2 or immediate).
    pub c: u64,
    /// Result value (0 or 1).
    pub a: u64,
    /// Opcode: SLT=0, SLTU=1 (signed vs unsigned comparison).
    pub opcode: u8,

    // From ALUTypeRecord
    /// Destination register number (rd).
    pub op_a: u8,
    /// Source register 1 spec (rs1).
    pub op_b: u64,
    /// Source register 2 or immediate value.
    pub op_c: u64,
    /// Whether op_c is an immediate value.
    pub is_imm: bool,

    /// Memory access record for destination register (write).
    pub mem_a: GpuMemoryAccess,
    /// Memory access record for source register 1 (read).
    pub mem_b: GpuMemoryAccess,
    /// Memory access record for source register 2 (read). Only valid if !is_imm.
    pub mem_c: GpuMemoryAccess,
}

/// GPU-compatible event for BitwiseChip (XOR, OR, AND, XORI, ORI, ANDI).
///
/// This flattens `AluEvent` and `ALUTypeRecord` into a single struct without Options or enums.
/// BitwiseChip uses ALUTypeReader since it supports both register and immediate modes.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct BitwiseGpuEvent {
    // From AluEvent
    /// Clock cycle of this instruction.
    pub clk: u64,
    /// Program counter of this instruction.
    pub pc: u64,
    /// First operand value (from rs1).
    pub b: u64,
    /// Second operand value (from rs2 or immediate).
    pub c: u64,
    /// Result value.
    pub a: u64,
    /// Opcode: XOR=0, OR=1, AND=2.
    pub opcode: u8,

    // From ALUTypeRecord
    /// Destination register number (rd).
    pub op_a: u8,
    /// Source register 1 spec (rs1).
    pub op_b: u64,
    /// Source register 2 or immediate value.
    pub op_c: u64,
    /// Whether op_c is an immediate value.
    pub is_imm: bool,

    /// Memory access record for destination register (write).
    pub mem_a: GpuMemoryAccess,
    /// Memory access record for source register 1 (read).
    pub mem_b: GpuMemoryAccess,
    /// Memory access record for source register 2 (read). Only valid if !is_imm.
    pub mem_c: GpuMemoryAccess,
}

/// GPU-compatible event for ShiftLeftChip (SLL, SLLI, SLLW, SLLIW).
///
/// This flattens `AluEvent` and `ALUTypeRecord` into a single struct without Options or enums.
/// ShiftLeftChip uses ALUTypeReader since it supports both register and immediate modes.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct ShiftLeftGpuEvent {
    // From AluEvent
    /// Clock cycle of this instruction.
    pub clk: u64,
    /// Program counter of this instruction.
    pub pc: u64,
    /// First operand value (from rs1).
    pub b: u64,
    /// Second operand value (shift amount from rs2 or immediate).
    pub c: u64,
    /// Result value.
    pub a: u64,
    /// Opcode: SLL=0, SLLW=1.
    pub opcode: u8,

    // From ALUTypeRecord
    /// Destination register number (rd).
    pub op_a: u8,
    /// Source register 1 spec (rs1).
    pub op_b: u64,
    /// Source register 2 or immediate value (shift amount).
    pub op_c: u64,
    /// Whether op_c is an immediate value.
    pub is_imm: bool,

    /// Memory access record for destination register (write).
    pub mem_a: GpuMemoryAccess,
    /// Memory access record for source register 1 (read).
    pub mem_b: GpuMemoryAccess,
    /// Memory access record for source register 2 (read). Only valid if !is_imm.
    pub mem_c: GpuMemoryAccess,
}
