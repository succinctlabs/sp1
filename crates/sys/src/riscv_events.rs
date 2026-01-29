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

/// GPU-compatible event for ShiftRightChip (SRL, SRLI, SRA, SRAI, SRLW, SRLIW, SRAW, SRAIW).
///
/// This flattens `AluEvent` and `ALUTypeRecord` into a single struct without Options or enums.
/// ShiftRightChip uses ALUTypeReader since it supports both register and immediate modes.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct ShiftRightGpuEvent {
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
    /// Opcode value to distinguish shift variants.
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

/// GPU-compatible event for ShiftLeftChip (SLL, SLLI, SLLW, SLLIW).
///
/// Uses the same layout as ShiftRightGpuEvent since both use ALUTypeReader.
pub type ShiftLeftGpuEvent = ShiftRightGpuEvent;

/// GPU-compatible event for memory store instructions (SB, SH, SW, SD).
///
/// This flattens `MemInstrEvent` and `ITypeRecord` into a single struct without Options or enums.
/// Store chips use ITypeReader format (op_c is always an immediate offset).
/// Compared to LoadGpuEvent, this adds `store_value` for the new value written to memory.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct StoreGpuEvent {
    // From MemInstrEvent
    /// Clock cycle of this instruction.
    pub clk: u64,
    /// Program counter of this instruction.
    pub pc: u64,
    /// Base address value (from rs1).
    pub b: u64,
    /// Offset value (immediate).
    pub c: u64,
    /// Value being stored (register value).
    pub a: u64,

    // Memory access for the data store
    /// The previous value at the memory location (before write).
    pub mem_access_prev_value: u64,
    /// The new value at the memory location (after write).
    pub mem_access_new_value: u64,
    /// Previous timestamp of the memory location.
    pub mem_access_prev_timestamp: u64,
    /// Current timestamp of the memory access.
    pub mem_access_current_timestamp: u64,

    // From ITypeRecord
    /// Destination register number (rd / rs2 for stores).
    pub op_a: u8,
    /// Source register 1 spec (rs1).
    pub op_b: u64,
    /// Immediate value (offset).
    pub op_c: u64,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,

    /// Memory access record for destination register.
    pub mem_a: GpuMemoryAccess,
    /// Memory access record for source register 1 (read).
    pub mem_b: GpuMemoryAccess,
}

/// GPU-compatible event for UTypeChip (LUI, AUIPC).
///
/// This flattens `UTypeEvent` and `JTypeRecord` into a single struct without Options or enums.
/// JTypeRecord uses J-type instruction format where op_b and op_c are always immediates,
/// and only op_a is a register (write).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct UTypeGpuEvent {
    // From UTypeEvent
    /// Clock cycle of this instruction.
    pub clk: u64,
    /// Program counter of this instruction.
    pub pc: u64,
    /// Result value (written to rd).
    pub a: u64,
    /// The b operand value (immediate).
    pub b: u64,
    /// The c operand value (immediate).
    pub c: u64,
    /// Whether the opcode is AUIPC (true) or LUI (false).
    pub is_auipc: bool,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,

    // From JTypeRecord
    /// Destination register number (rd).
    pub op_a: u8,
    /// Immediate operand b value.
    pub op_b: u64,
    /// Immediate operand c value.
    pub op_c: u64,

    /// Memory access record for destination register (write).
    pub mem_a: GpuMemoryAccess,
}

/// GPU-compatible event for BranchChip (BEQ, BNE, BLT, BGE, BLTU, BGEU).
///
/// This flattens `BranchEvent` and `ITypeRecord` into a single struct without Options or enums.
/// BranchChip uses ITypeReader (op_a and op_b are registers, op_c is an immediate).
/// Unlike most other chips, BranchEvent has `next_pc` and 6 opcode variants.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct BranchGpuEvent {
    // From BranchEvent
    /// Clock cycle of this instruction.
    pub clk: u64,
    /// Program counter of this instruction.
    pub pc: u64,
    /// Next program counter (target if branching, pc+4 if not).
    pub next_pc: u64,
    /// The first operand value (from rs1).
    pub a: u64,
    /// The second operand value (from rs2).
    pub b: u64,
    /// The third operand value (immediate offset).
    pub c: u64,
    /// Opcode: BEQ=0, BNE=1, BLT=2, BGE=3, BLTU=4, BGEU=5.
    pub opcode: u8,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,

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

/// GPU-compatible event for JalChip (JAL instruction).
///
/// This flattens `JumpEvent` and `JTypeRecord` into a single struct without Options or enums.
/// JalChip uses JTypeReader (op_b and op_c are immediates, only op_a is a register write).
/// JAL computes next_pc = pc + offset and saves return address (pc + 4) in rd.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct JalGpuEvent {
    // From JumpEvent
    /// Clock cycle of this instruction.
    pub clk: u64,
    /// Program counter of this instruction.
    pub pc: u64,
    /// The b operand value (jump offset immediate).
    pub b: u64,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,

    // From JTypeRecord
    /// Destination register number (rd).
    pub op_a: u8,
    /// Immediate operand b value.
    pub op_b: u64,
    /// Immediate operand c value.
    pub op_c: u64,

    /// Memory access record for destination register (write).
    pub mem_a: GpuMemoryAccess,
}

/// GPU-compatible event for JalrChip (JALR instruction).
///
/// This flattens `JumpEvent` and `ITypeRecord` into a single struct without Options or enums.
/// JalrChip uses ITypeReader (op_b is a register read, op_c is an immediate).
/// JALR computes next_pc = rs1 + imm and saves return address (pc + 4) in rd.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct JalrGpuEvent {
    // From JumpEvent
    /// Clock cycle of this instruction.
    pub clk: u64,
    /// Program counter of this instruction.
    pub pc: u64,
    /// The return address value (a = pc + 4 if rd != x0, else 0).
    pub a: u64,
    /// The base register value (rs1).
    pub b: u64,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,

    // From ITypeRecord
    /// Destination register number (rd).
    pub op_a: u8,
    /// Source register 1 spec (rs1).
    pub op_b: u64,
    /// Immediate value (offset).
    pub op_c: u64,

    /// Memory access record for destination register (write).
    pub mem_a: GpuMemoryAccess,
    /// Memory access record for source register 1 (read).
    pub mem_b: GpuMemoryAccess,
}

/// GPU-compatible event for memory load instructions (LB, LBU, LH, LHU, LW, LWU, LD).
///
/// This flattens `MemInstrEvent` and `ITypeRecord` into a single struct without Options or enums.
/// All load chips use ITypeReader format (op_c is always an immediate offset).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct LoadGpuEvent {
    // From MemInstrEvent
    /// Clock cycle of this instruction.
    pub clk: u64,
    /// Program counter of this instruction.
    pub pc: u64,
    /// Base address value (from rs1).
    pub b: u64,
    /// Offset value (immediate).
    pub c: u64,
    /// Result value (loaded data, possibly sign-extended).
    pub a: u64,
    /// Opcode value to distinguish load variants.
    pub opcode: u8,

    // Memory access for the data load
    /// The value loaded from memory (prev_value of the memory location).
    pub mem_access_value: u64,
    /// Previous timestamp of the memory location.
    pub mem_access_prev_timestamp: u64,
    /// Current timestamp of the memory access.
    pub mem_access_current_timestamp: u64,

    // From ITypeRecord
    /// Destination register number (rd).
    pub op_a: u8,
    /// Source register 1 spec (rs1).
    pub op_b: u64,
    /// Immediate value (offset).
    pub op_c: u64,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,

    /// Memory access record for destination register (write).
    pub mem_a: GpuMemoryAccess,
    /// Memory access record for source register 1 (read).
    pub mem_b: GpuMemoryAccess,
}

/// GPU-compatible event for SyscallInstrsChip.
///
/// This flattens `SyscallEvent` and `RTypeRecord` into a single struct without Options or enums.
/// SyscallInstrsChip uses RTypeReader (all three operands are registers).
/// The syscall type is determined from the prev_value of op_a (register t0).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct SyscallInstrsGpuEvent {
    // From SyscallEvent
    /// Clock cycle of this instruction.
    pub clk: u64,
    /// Program counter of this instruction.
    pub pc: u64,
    /// The first argument (op_b value, i.e. register value of op_b).
    pub arg1: u64,
    /// The second argument (op_c value, i.e. register value of op_c).
    pub arg2: u64,
    /// The exit code (for HALT).
    pub exit_code: u32,
    /// The value written to op_a register (record.a.value()).
    /// Needed separately because GpuMemoryAccess only stores prev_value.
    pub a_value: u64,

    // From RTypeRecord
    /// Destination register number (op_a / t0).
    pub op_a: u8,
    /// Source register 1 spec (op_b).
    pub op_b: u64,
    /// Source register 2 spec (op_c).
    pub op_c: u64,

    /// Memory access record for op_a register.
    pub mem_a: GpuMemoryAccess,
    /// Memory access record for op_b register.
    pub mem_b: GpuMemoryAccess,
    /// Memory access record for op_c register.
    pub mem_c: GpuMemoryAccess,
}

/// GPU-compatible entry for ByteChip multiplicity scatter.
///
/// Each entry represents one HashMap entry from `byte_lookups` (excluding Range opcode).
/// The kernel writes `from_canonical_u32(mult)` to `trace[row + opcode * height]`.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct ByteLookupGpuEntry {
    /// Row index = (b << 8) + c.
    pub row: u32,
    /// Opcode index (0=AND, 1=OR, 2=XOR, 3=U8Range, 4=LTU, 5=MSB).
    pub opcode: u32,
    /// Multiplicity count.
    pub mult: u32,
}

/// GPU-compatible entry for RangeChip multiplicity scatter.
///
/// Each entry represents one HashMap entry from `byte_lookups` (Range opcode only).
/// The kernel writes `from_canonical_u32(mult)` to `trace[row]`.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct RangeLookupGpuEntry {
    /// Row index = a + (1 << b).
    pub row: u32,
    /// Multiplicity count.
    pub mult: u32,
}

/// GPU-compatible event for MemoryGlobalChip (Init and Finalize).
///
/// This mirrors `MemoryInitializeFinalizeEvent` which is already #[repr(C)].
/// Events must be sorted by address before sending to the GPU.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct MemoryGlobalGpuEvent {
    /// The memory address.
    pub addr: u64,
    /// The memory value.
    pub value: u64,
    /// The timestamp.
    pub timestamp: u64,
}

/// GPU-compatible event for SyscallChip (Core and Precompile).
///
/// This is a minimal struct containing only the fields needed for SyscallCols trace generation.
/// SyscallChip has only 11 columns and needs no memory access or adapter data.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct SyscallGpuEvent {
    /// Clock cycle.
    pub clk: u64,
    /// The syscall identifier (byte 0 of syscall code).
    pub syscall_id: u32,
    /// First argument.
    pub arg1: u64,
    /// Second argument.
    pub arg2: u64,
}
