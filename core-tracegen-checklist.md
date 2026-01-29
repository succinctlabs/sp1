# Core RISC-V GPU Tracegen Implementation Checklist

This document tracks the GPU tracegen implementation status for core RISC-V chips.

## ALU Instructions

| Chip | Variant | GPU Impl | Stub | Tests | Perf | Integ | File |
|------|---------|----------|------|-------|------|-------|------|
| AddChip | `Add` | [x] | [x] | [x] | [x] | [x] | `alu.rs` |
| AddwChip | `Addw` | [x] | [x] | [x] | [x] | [x] | `alu.rs` |
| AddiChip | `Addi` | [x] | [x] | [x] | [x] | [x] | `alu.rs` |
| SubChip | `Sub` | [x] | [x] | [x] | [x] | [x] | `alu.rs` |
| SubwChip | `Subw` | [x] | [x] | [x] | [x] | [x] | `alu.rs` |
| MulChip | `Mul` | [x] | [x] | [x] | [x] | [x] | `alu.rs` |
| DivRemChip | `DivRem` | [x] | [x] | [x] | [x] | [x] | `alu.rs` |
| LtChip | `Lt` | [x] | [x] | [x] | [x] | [x] | `alu.rs` |

## Bitwise Instructions

| Chip | Variant | GPU Impl | Stub | Tests | Perf | Integ | File |
|------|---------|----------|------|-------|------|-------|------|
| BitwiseChip | `Bitwise` | [x] | [x] | [x] | [x] | [x] | `bitwise.rs` |

## Shift Instructions

| Chip | Variant | GPU Impl | Stub | Tests | Perf | Integ | File |
|------|---------|----------|------|-------|------|-------|------|
| ShiftLeft | `ShiftLeft` | [x] | [x] | [x] | [x] | [ ] | `shift.rs` |
| ShiftRightChip | `ShiftRight` | [x] | [x] | [x] | [x] | [ ] | `shift.rs` |

## Memory Load Instructions

| Chip | Variant | GPU Impl | Stub | Tests | Perf | Integ | File |
|------|---------|----------|------|-------|------|-------|------|
| LoadByteChip | `LoadByte` | [x] | [x] | [x] | [x] | [ ] | `memory_load.rs` |
| LoadHalfChip | `LoadHalf` | [x] | [x] | [x] | [x] | [ ] | `memory_load.rs` |
| LoadWordChip | `LoadWord` | [x] | [x] | [x] | [x] | [ ] | `memory_load.rs` |
| LoadDoubleChip | `LoadDouble` | [x] | [x] | [x] | [x] | [ ] | `memory_load.rs` |
| LoadX0Chip | `LoadX0` | [x] | [x] | [x] | [x] | [ ] | `memory_load.rs` |

## Memory Store Instructions

| Chip | Variant | GPU Impl | Stub | Tests | Perf | Integ | File |
|------|---------|----------|------|-------|------|-------|------|
| StoreByteChip | `StoreByte` | [x] | [x] | [x] | [x] | [ ] | `memory_store.rs` |
| StoreHalfChip | `StoreHalf` | [x] | [x] | [x] | [x] | [ ] | `memory_store.rs` |
| StoreWordChip | `StoreWord` | [x] | [x] | [x] | [x] | [ ] | `memory_store.rs` |
| StoreDoubleChip | `StoreDouble` | [x] | [x] | [x] | [x] | [ ] | `memory_store.rs` |

## Control Flow Instructions

| Chip | Variant | GPU Impl | Stub | Tests | Perf | Integ | File |
|------|---------|----------|------|-------|------|-------|------|
| UTypeChip | `UType` | [x] | [x] | [x] | [x] | [ ] | `control_flow.rs` |
| BranchChip | `Branch` | [x] | [x] | [x] | [x] | [ ] | `control_flow.rs` |
| JalChip | `Jal` | [x] | [x] | [x] | [x] | [ ] | `control_flow.rs` |
| JalrChip | `Jalr` | [x] | [x] | [x] | [x] | [ ] | `control_flow.rs` |

## Syscall Instructions

| Chip | Variant | GPU Impl | Stub | Tests | Perf | Integ | File |
|------|---------|----------|------|-------|------|-------|------|
| SyscallInstrsChip | `SyscallInstrs` | [x] | [x] | [x] | [x] | [ ] | `syscall.rs` |
| SyscallChip | `SyscallCore` | [x] | [x] | [x] | [x] | [ ] | `syscall.rs` |
| SyscallChip | `SyscallPrecompile` | [x] | [x] | [x] | [x] | [ ] | `syscall.rs` |

## Lookup Tables

| Chip | Variant | GPU Impl | Stub | Tests | Perf | Integ | File |
|------|---------|----------|------|-------|------|-------|------|
| ByteChip | `ByteLookup` | [x] | [x] | [x] | [x] | [ ] | `lookup.rs` |
| RangeChip | `RangeLookup` | [x] | [x] | [x] | [x] | [ ] | `lookup.rs` |

## Memory State

| Chip | Variant | GPU Impl | Stub | Tests | Perf | Integ | File |
|------|---------|----------|------|-------|------|-------|------|
| MemoryGlobalChip | `MemoryGlobalInit` | [x] | [x] | [x] | [x] | [ ] | `memory_state.rs` |
| MemoryGlobalChip | `MemoryGlobalFinal` | [x] | [x] | [x] | [x] | [ ] | `memory_state.rs` |
| MemoryLocalChip | `MemoryLocal` | [x] | [x] | [x] | [x] | [ ] | `memory_state.rs` |
| MemoryBumpChip | `MemoryBump` | [x] | [x] | [x] | [x] | [ ] | `memory_state.rs` |
| StateBumpChip | `StateBump` | [x] | [x] | [x] | [x] | [ ] | `memory_state.rs` |

## Program

| Chip | Variant | GPU Impl | Stub | Tests | Perf | Integ | File |
|------|---------|----------|------|-------|------|-------|------|
| ProgramChip | `Program` | [x] | [x] | [x] | [x] | [x] | `program.rs` |

## Global Interactions

| Chip | Variant | GPU Impl | Stub | Tests | Perf | Integ | File |
|------|---------|----------|------|-------|------|-------|------|
| GlobalChip | `Global` | [x] | [x] | [x] | [x] | [x] | `global.rs` |

## Summary

- **Total core chips**: 35
- **GPU implemented**: 35 (Global, Add, Addw, Addi, Sub, Subw, Mul, DivRem, Lt, Bitwise, ShiftLeft, ShiftRight, LoadByte, LoadHalf, LoadWord, LoadDouble, LoadX0, StoreByte, StoreHalf, StoreWord, StoreDouble, UType, Branch, Jal, Jalr, SyscallInstrs, SyscallCore, SyscallPrecompile, ByteLookup, RangeLookup, MemoryLocal, MemoryBump, StateBump, Program, MemoryGlobalInit+Finalize)
- **Stubs created**: 35
- **Tests passing**: 35
- **Perf checked**: 35 (all chips complete)
- **Integration enabled**: 9 (Global, Program, Add, Addw, Addi, Sub, Subw, Mul, DivRem)

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
