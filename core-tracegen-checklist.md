# Core RISC-V GPU Tracegen Implementation Checklist

This document tracks the GPU tracegen implementation status for core RISC-V chips.

## ALU Instructions

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| AddChip | `Add` | [x] | [x] | [x] | `alu.rs` |
| AddwChip | `Addw` | [x] | [x] | [x] | `alu.rs` |
| AddiChip | `Addi` | [x] | [x] | [x] | `alu.rs` |
| SubChip | `Sub` | [x] | [x] | [x] | `alu.rs` |
| SubwChip | `Subw` | [ ] | [x] | [ ] | `alu.rs` |
| MulChip | `Mul` | [ ] | [x] | [ ] | `alu.rs` |
| DivRemChip | `DivRem` | [ ] | [x] | [ ] | `alu.rs` |
| LtChip | `Lt` | [ ] | [x] | [ ] | `alu.rs` |

## Bitwise Instructions

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| BitwiseChip | `Bitwise` | [ ] | [x] | [ ] | `bitwise.rs` |

## Shift Instructions

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| ShiftLeft | `ShiftLeft` | [ ] | [x] | [ ] | `shift.rs` |
| ShiftRightChip | `ShiftRight` | [ ] | [x] | [ ] | `shift.rs` |

## Memory Load Instructions

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| LoadByteChip | `LoadByte` | [ ] | [x] | [ ] | `memory_load.rs` |
| LoadHalfChip | `LoadHalf` | [ ] | [x] | [ ] | `memory_load.rs` |
| LoadWordChip | `LoadWord` | [ ] | [x] | [ ] | `memory_load.rs` |
| LoadDoubleChip | `LoadDouble` | [ ] | [x] | [ ] | `memory_load.rs` |
| LoadX0Chip | `LoadX0` | [ ] | [x] | [ ] | `memory_load.rs` |

## Memory Store Instructions

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| StoreByteChip | `StoreByte` | [ ] | [x] | [ ] | `memory_store.rs` |
| StoreHalfChip | `StoreHalf` | [ ] | [x] | [ ] | `memory_store.rs` |
| StoreWordChip | `StoreWord` | [ ] | [x] | [ ] | `memory_store.rs` |
| StoreDoubleChip | `StoreDouble` | [ ] | [x] | [ ] | `memory_store.rs` |

## Control Flow Instructions

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| UTypeChip | `UType` | [ ] | [x] | [ ] | `control_flow.rs` |
| BranchChip | `Branch` | [ ] | [x] | [ ] | `control_flow.rs` |
| JalChip | `Jal` | [ ] | [x] | [ ] | `control_flow.rs` |
| JalrChip | `Jalr` | [ ] | [x] | [ ] | `control_flow.rs` |

## Syscall Instructions

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| SyscallInstrsChip | `SyscallInstrs` | [ ] | [x] | [ ] | `syscall.rs` |
| SyscallChip | `SyscallCore` | [ ] | [x] | [ ] | `syscall.rs` |
| SyscallChip | `SyscallPrecompile` | [ ] | [x] | [ ] | `syscall.rs` |

## Lookup Tables

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| ByteChip | `ByteLookup` | [ ] | [x] | [ ] | `lookup.rs` |
| RangeChip | `RangeLookup` | [ ] | [x] | [ ] | `lookup.rs` |

## Memory State

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| MemoryGlobalChip | `MemoryGlobalInit` | [ ] | [x] | [ ] | `memory_state.rs` |
| MemoryGlobalChip | `MemoryGlobalFinal` | [ ] | [x] | [ ] | `memory_state.rs` |
| MemoryLocalChip | `MemoryLocal` | [ ] | [x] | [ ] | `memory_state.rs` |
| MemoryBumpChip | `MemoryBump` | [ ] | [x] | [ ] | `memory_state.rs` |
| StateBumpChip | `StateBump` | [ ] | [x] | [ ] | `memory_state.rs` |

## Program

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| ProgramChip | `Program` | [ ] | [x] | [ ] | `program.rs` |

## Global Interactions

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| GlobalChip | `Global` | [x] | [x] | [x] | `global.rs` |

## Summary

- **Total core chips**: 35
- **GPU implemented**: 5 (Global, Add, Addw, Addi, Sub)
- **Stubs created**: 35
- **Tests passing**: 5

## File Structure

```
crates/tracegen/src/riscv/
├── mod.rs
├── global.rs          # DONE - Global interactions
├── alu.rs             # Add, Addw, Addi, Sub, Subw, Mul, DivRem, Lt
├── bitwise.rs         # Bitwise (AND, OR, XOR)
├── shift.rs           # ShiftLeft, ShiftRight
├── memory_load.rs     # LoadByte, LoadHalf, LoadWord, LoadDouble, LoadX0
├── memory_store.rs    # StoreByte, StoreHalf, StoreWord, StoreDouble
├── control_flow.rs    # UType, Branch, Jal, Jalr
├── syscall.rs         # SyscallInstrs, SyscallChip (core/precompile)
├── lookup.rs          # ByteChip, RangeChip
├── memory_state.rs    # MemoryGlobal, MemoryLocal, MemoryBump, StateBump
├── program.rs         # ProgramChip
└── precompiles/       # See precompile-tracegen-checklist.md
```
