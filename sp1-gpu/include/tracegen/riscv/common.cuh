/// Common CUDA helpers for RISC-V GPU trace generation.
///
/// This header provides shared functions used across multiple RISC-V chip
/// tracegen implementations to avoid code duplication.

#pragma once

#include "sp1-gpu-cbindgen.hpp"
#include "fields/kb31_t.cuh"

namespace riscv_tracegen {

/// Convert a u64 value to a Word<T> (4 x 16-bit limbs stored as field elements).
template <class T>
__device__ void u64_to_word(uint64_t value, sp1_gpu_sys::Word<T>& word) {
    word._0[0] = T::from_canonical_u32(value & 0xFFFF);
    word._0[1] = T::from_canonical_u32((value >> 16) & 0xFFFF);
    word._0[2] = T::from_canonical_u32((value >> 32) & 0xFFFF);
    word._0[3] = T::from_canonical_u32((value >> 48) & 0xFFFF);
}

/// Populate RegisterAccessTimestamp from prev_timestamp and current_timestamp.
template <class T>
__device__ void populate_register_access_timestamp(
    sp1_gpu_sys::RegisterAccessTimestamp<T>& ts,
    uint64_t prev_timestamp,
    uint64_t current_timestamp) {
    // Extract high and low parts of timestamps
    uint32_t prev_high = prev_timestamp >> 24;
    uint32_t prev_low_val = prev_timestamp & 0xFFFFFF;
    uint32_t current_high = current_timestamp >> 24;
    uint32_t current_low_val = current_timestamp & 0xFFFFFF;

    // If in same high region, use actual prev_low; otherwise use 0
    uint32_t old_timestamp = (prev_high == current_high) ? prev_low_val : 0;
    ts.prev_low = T::from_canonical_u32(old_timestamp);

    // Compute diff_low_limb
    uint32_t diff_minus_one = current_low_val - old_timestamp - 1;
    uint16_t diff_low_limb = diff_minus_one & 0xFFFF;
    ts.diff_low_limb = T::from_canonical_u32(diff_low_limb);
}

/// Populate RegisterAccessCols from GpuMemoryAccess.
template <class T>
__device__ void populate_register_access_cols(
    sp1_gpu_sys::RegisterAccessCols<T>& cols,
    const sp1_gpu_sys::GpuMemoryAccess& mem) {
    u64_to_word(mem.prev_value, cols.prev_value);
    populate_register_access_timestamp(
        cols.access_timestamp,
        mem.prev_timestamp,
        mem.current_timestamp);
}

/// Populate CPUState from clock and program counter.
///
/// IMPORTANT: PC uses 3 x 16-bit limbs, NOT 22-bit!
/// Reference: sp1-wip/crates/core/machine/src/adapter/state.rs:58-61
template <class T>
__device__ void populate_cpu_state(sp1_gpu_sys::CPUState<T>& state, uint64_t clk, uint64_t pc) {
    // Clock encoding: high 24 bits, mid 8 bits (16-24), low 16 bits (0-16)
    state.clk_high = T::from_canonical_u32(clk >> 24);
    state.clk_16_24 = T::from_canonical_u32((clk >> 16) & 0xFF);
    state.clk_0_16 = T::from_canonical_u32(clk & 0xFFFF);

    // PC encoding: 3 x 16-bit limbs
    state.pc[0] = T::from_canonical_u32(pc & 0xFFFF);
    state.pc[1] = T::from_canonical_u32((pc >> 16) & 0xFFFF);
    state.pc[2] = T::from_canonical_u32((pc >> 32) & 0xFFFF);
}

/// Populate RTypeReader from R-type instruction event data.
/// Works with AddGpuEvent and similar R-type event structures.
template <class T, class Event>
__device__ void populate_r_type_reader(sp1_gpu_sys::RTypeReader<T>& adapter, const Event& event) {
    adapter.op_a = T::from_canonical_u32(event.op_a);
    populate_register_access_cols(adapter.op_a_memory, event.mem_a);
    adapter.op_a_0 = T::from_bool(event.op_a == 0);

    // op_b and op_c are register specifiers, which are small values
    adapter.op_b = T::from_canonical_u32(static_cast<uint32_t>(event.op_b));
    populate_register_access_cols(adapter.op_b_memory, event.mem_b);

    adapter.op_c = T::from_canonical_u32(static_cast<uint32_t>(event.op_c));
    populate_register_access_cols(adapter.op_c_memory, event.mem_c);
}

/// Populate ALUTypeReader from ALU-type instruction event data.
/// Used by AddwChip and similar chips that support immediate mode.
template <class T>
__device__ void populate_alu_type_reader(
    sp1_gpu_sys::ALUTypeReader<T>& adapter,
    const sp1_gpu_sys::AddwGpuEvent& event) {
    adapter.op_a = T::from_canonical_u32(event.op_a);
    populate_register_access_cols(adapter.op_a_memory, event.mem_a);
    adapter.op_a_0 = T::from_bool(event.op_a == 0);

    // op_b is a register specifier
    adapter.op_b = T::from_canonical_u32(static_cast<uint32_t>(event.op_b));
    populate_register_access_cols(adapter.op_b_memory, event.mem_b);

    // op_c is stored as a Word (4 x u16 limbs)
    u64_to_word(event.op_c, adapter.op_c);

    // Handle immediate vs register for op_c
    adapter.imm_c = T::from_bool(event.is_imm);
    if (event.is_imm) {
        // When it's an immediate, op_c_memory.prev_value = op_c, and timestamps are zero
        adapter.op_c_memory.prev_value = adapter.op_c;
        adapter.op_c_memory.access_timestamp.diff_low_limb = T::zero();
        adapter.op_c_memory.access_timestamp.prev_low = T::zero();
    } else {
        // When it's a register read, populate from memory access
        populate_register_access_cols(adapter.op_c_memory, event.mem_c);
    }
}

/// Populate ITypeReader from I-type instruction event data.
/// Used by AddiChip, JalrChip, and similar I-type instructions.
template <class T, class Event>
__device__ void populate_i_type_reader(sp1_gpu_sys::ITypeReader<T>& adapter, const Event& event) {
    adapter.op_a = T::from_canonical_u32(event.op_a);
    populate_register_access_cols(adapter.op_a_memory, event.mem_a);
    adapter.op_a_0 = T::from_bool(event.op_a == 0);

    // op_b is a register specifier
    adapter.op_b = T::from_canonical_u32(static_cast<uint32_t>(event.op_b));
    populate_register_access_cols(adapter.op_b_memory, event.mem_b);

    // op_c is an immediate value stored as a Word
    u64_to_word(event.op_c, adapter.op_c_imm);
}

} // namespace riscv_tracegen
