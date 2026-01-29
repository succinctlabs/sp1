# Core RISC-V GPU Tracegen Implementation Checklist

This document tracks the GPU tracegen implementation status for core RISC-V chips.

## ALU Instructions

| Chip | Variant | GPU Impl | Stub | Tests | Perf | File |
|------|---------|----------|------|-------|------|------|
| AddChip | `Add` | [x] | [x] | [x] | [x] | `alu.rs` |
| AddwChip | `Addw` | [x] | [x] | [x] | [x] | `alu.rs` |
| AddiChip | `Addi` | [x] | [x] | [x] | [x] | `alu.rs` |
| SubChip | `Sub` | [x] | [x] | [x] | [x] | `alu.rs` |
| SubwChip | `Subw` | [x] | [x] | [x] | [x] | `alu.rs` |
| MulChip | `Mul` | [x] | [x] | [x] | [x] | `alu.rs` |
| DivRemChip | `DivRem` | [x] | [x] | [x] | [ ] | `alu.rs` |
| LtChip | `Lt` | [x] | [x] | [x] | [x] | `alu.rs` |

## Bitwise Instructions

| Chip | Variant | GPU Impl | Stub | Tests | Perf | File |
|------|---------|----------|------|-------|------|------|
| BitwiseChip | `Bitwise` | [x] | [x] | [x] | [x] | `bitwise.rs` |

## Shift Instructions

| Chip | Variant | GPU Impl | Stub | Tests | Perf | File |
|------|---------|----------|------|-------|------|------|
| ShiftLeft | `ShiftLeft` | [x] | [x] | [x] | [x] | `shift.rs` |
| ShiftRightChip | `ShiftRight` | [x] | [x] | [x] | [x] | `shift.rs` |

## Memory Load Instructions

| Chip | Variant | GPU Impl | Stub | Tests | Perf | File |
|------|---------|----------|------|-------|------|------|
| LoadByteChip | `LoadByte` | [x] | [x] | [x] | [x] | `memory_load.rs` |
| LoadHalfChip | `LoadHalf` | [x] | [x] | [x] | [x] | `memory_load.rs` |
| LoadWordChip | `LoadWord` | [x] | [x] | [x] | [x] | `memory_load.rs` |
| LoadDoubleChip | `LoadDouble` | [x] | [x] | [x] | [x] | `memory_load.rs` |
| LoadX0Chip | `LoadX0` | [x] | [x] | [x] | [x] | `memory_load.rs` |

## Memory Store Instructions

| Chip | Variant | GPU Impl | Stub | Tests | Perf | File |
|------|---------|----------|------|-------|------|------|
| StoreByteChip | `StoreByte` | [x] | [x] | [x] | [x] | `memory_store.rs` |
| StoreHalfChip | `StoreHalf` | [x] | [x] | [x] | [x] | `memory_store.rs` |
| StoreWordChip | `StoreWord` | [x] | [x] | [x] | [x] | `memory_store.rs` |
| StoreDoubleChip | `StoreDouble` | [x] | [x] | [x] | [x] | `memory_store.rs` |

## Control Flow Instructions

| Chip | Variant | GPU Impl | Stub | Tests | Perf | File |
|------|---------|----------|------|-------|------|------|
| UTypeChip | `UType` | [x] | [x] | [x] | [x] | `control_flow.rs` |
| BranchChip | `Branch` | [ ] | [x] | [ ] | [ ] | `control_flow.rs` |
| JalChip | `Jal` | [ ] | [x] | [ ] | [ ] | `control_flow.rs` |
| JalrChip | `Jalr` | [ ] | [x] | [ ] | [ ] | `control_flow.rs` |

## Syscall Instructions

| Chip | Variant | GPU Impl | Stub | Tests | Perf | File |
|------|---------|----------|------|-------|------|------|
| SyscallInstrsChip | `SyscallInstrs` | [ ] | [x] | [ ] | [ ] | `syscall.rs` |
| SyscallChip | `SyscallCore` | [ ] | [x] | [ ] | [ ] | `syscall.rs` |
| SyscallChip | `SyscallPrecompile` | [ ] | [x] | [ ] | [ ] | `syscall.rs` |

## Lookup Tables

| Chip | Variant | GPU Impl | Stub | Tests | Perf | File |
|------|---------|----------|------|-------|------|------|
| ByteChip | `ByteLookup` | [ ] | [x] | [ ] | [ ] | `lookup.rs` |
| RangeChip | `RangeLookup` | [ ] | [x] | [ ] | [ ] | `lookup.rs` |

## Memory State

| Chip | Variant | GPU Impl | Stub | Tests | Perf | File |
|------|---------|----------|------|-------|------|------|
| MemoryGlobalChip | `MemoryGlobalInit` | [ ] | [x] | [ ] | [ ] | `memory_state.rs` |
| MemoryGlobalChip | `MemoryGlobalFinal` | [ ] | [x] | [ ] | [ ] | `memory_state.rs` |
| MemoryLocalChip | `MemoryLocal` | [ ] | [x] | [ ] | [ ] | `memory_state.rs` |
| MemoryBumpChip | `MemoryBump` | [ ] | [x] | [ ] | [ ] | `memory_state.rs` |
| StateBumpChip | `StateBump` | [ ] | [x] | [ ] | [ ] | `memory_state.rs` |

## Program

| Chip | Variant | GPU Impl | Stub | Tests | Perf | File |
|------|---------|----------|------|-------|------|------|
| ProgramChip | `Program` | [ ] | [x] | [ ] | [ ] | `program.rs` |

## Global Interactions

| Chip | Variant | GPU Impl | Stub | Tests | Perf | File |
|------|---------|----------|------|-------|------|------|
| GlobalChip | `Global` | [x] | [x] | [x] | [x] | `global.rs` |

## Summary

- **Total core chips**: 35
- **GPU implemented**: 22 (Global, Add, Addw, Addi, Sub, Subw, Mul, DivRem, Lt, Bitwise, ShiftLeft, ShiftRight, LoadByte, LoadHalf, LoadWord, LoadDouble, LoadX0, StoreByte, StoreHalf, StoreWord, StoreDouble, UType)
- **Stubs created**: 35
- **Tests passing**: 22
- **Perf checked**: 21 (all implemented except DivRem which is disabled)

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
