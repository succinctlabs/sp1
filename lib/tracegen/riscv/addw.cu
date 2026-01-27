/// GPU trace generation for RISC-V AddwChip.

#include "sp1-gpu-cbindgen.hpp"

#include "fields/kb31_t.cuh"

// Manually define AddwOperation since cbindgen can't handle WORD_SIZE / 2 constant expression.
// This matches the Rust struct: value: [T; WORD_SIZE / 2] (i.e., [T; 2]) and msb: U16MSBOperation<T>
namespace sp1_gpu_sys {
template<typename T>
struct AddwOperation {
    /// The result of the ADDW operation (2 x u16 limbs).
    T value[2];
    /// The msb of the result.
    U16MSBOperation<T> msb;
};
} // namespace sp1_gpu_sys

/// Helper to convert a u64 value to a Word<T> (4 x u16 limbs stored as field elements).
template <class T>
__device__ void u64_to_word(const uint64_t value, sp1_gpu_sys::Word<T>& word) {
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
    populate_register_access_timestamp(cols.access_timestamp, mem.prev_timestamp, mem.current_timestamp);
}

/// Populate CPUState from clock and program counter.
template <class T>
__device__ void populate_cpu_state(sp1_gpu_sys::CPUState<T>& state, uint64_t clk, uint64_t pc) {
    uint32_t clk_high = clk >> 24;
    uint8_t clk_16_24 = (clk >> 16) & 0xFF;
    uint16_t clk_0_16 = clk & 0xFFFF;

    state.clk_high = T::from_canonical_u32(clk_high);
    state.clk_16_24 = T::from_canonical_u32(clk_16_24);
    state.clk_0_16 = T::from_canonical_u32(clk_0_16);

    // PC is stored as 3 x 22-bit limbs
    state.pc[0] = T::from_canonical_u32(pc & 0x3FFFFF);
    state.pc[1] = T::from_canonical_u32((pc >> 22) & 0x3FFFFF);
    state.pc[2] = T::from_canonical_u32((pc >> 44) & 0x3FFFFF);
}

/// Populate ALUTypeReader from the GPU event data.
template <class T>
__device__ void populate_alu_type_reader(sp1_gpu_sys::ALUTypeReader<T>& adapter, const sp1_gpu_sys::AddwGpuEvent& event) {
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

/// Populate AddwOperation from operands b and c.
/// ADDW computes a 32-bit add of the lower 32 bits and sign-extends the result.
template <class T>
__device__ void populate_addw_operation(sp1_gpu_sys::AddwOperation<T>& op, uint64_t b, uint64_t c) {
    // ADDW: add lower 32 bits, result is sign-extended 32-bit
    uint32_t result = static_cast<uint32_t>(b) + static_cast<uint32_t>(c);

    // Store result as 2 x u16 limbs (ADDW only uses lower 32 bits)
    op.value[0] = T::from_canonical_u32(result & 0xFFFF);
    op.value[1] = T::from_canonical_u32((result >> 16) & 0xFFFF);

    // Compute MSB of the result (bit 31 of result, which is bit 15 of value[1])
    uint16_t high_limb = (result >> 16) & 0xFFFF;
    uint32_t msb = (high_limb >> 15) & 1;
    op.msb.msb = T::from_canonical_u32(msb);
}

/// Main kernel for AddwChip trace generation.
template <class T>
__global__ void riscv_addw_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::AddwGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::AddwCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::AddwCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            // Populate is_real
            cols.is_real = T::one();

            // Populate addw_operation from b and c
            populate_addw_operation(cols.addw_operation, event.b, event.c);

            // Populate CPUState from clk and pc
            populate_cpu_state(cols.state, event.clk, event.pc);

            // Populate ALUTypeReader from event
            populate_alu_type_reader(cols.adapter, event);
        }

        // Write to trace in column-major format
        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr riscv_addw_generate_trace_kernel() {
    return (KernelPtr)::riscv_addw_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
