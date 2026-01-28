/// GPU trace generation for RISC-V AddiChip.

#include "sp1-gpu-cbindgen.hpp"

#include "fields/kb31_t.cuh"

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

    // PC is stored as 3 x 16-bit limbs
    state.pc[0] = T::from_canonical_u32(pc & 0xFFFF);
    state.pc[1] = T::from_canonical_u32((pc >> 16) & 0xFFFF);
    state.pc[2] = T::from_canonical_u32((pc >> 32) & 0xFFFF);
}

/// Populate ITypeReader from the GPU event data.
/// I-type instructions have op_a (rd) and op_b (rs1) as registers, and op_c as an immediate.
template <class T>
__device__ void populate_i_type_reader(sp1_gpu_sys::ITypeReader<T>& adapter, const sp1_gpu_sys::AddiGpuEvent& event) {
    adapter.op_a = T::from_canonical_u32(event.op_a);
    populate_register_access_cols(adapter.op_a_memory, event.mem_a);
    adapter.op_a_0 = T::from_bool(event.op_a == 0);

    // op_b is a register specifier
    adapter.op_b = T::from_canonical_u32(static_cast<uint32_t>(event.op_b));
    populate_register_access_cols(adapter.op_b_memory, event.mem_b);

    // op_c is an immediate value stored as a Word
    u64_to_word(event.op_c, adapter.op_c_imm);
}

/// Populate AddOperation from operands b and c.
/// The add operation stores value = b + c.
template <class T>
__device__ void populate_add_operation(sp1_gpu_sys::AddOperation<T>& op, uint64_t b, uint64_t c) {
    uint64_t result = b + c; // wrapping add
    u64_to_word(result, op.value);
}

/// Main kernel for AddiChip trace generation.
template <class T>
__global__ void riscv_addi_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::AddiGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::AddiCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::AddiCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            // Populate is_real
            cols.is_real = T::one();

            // Populate add_operation from b and c
            populate_add_operation(cols.add_operation, event.b, event.c);

            // Populate CPUState from clk and pc
            populate_cpu_state(cols.state, event.clk, event.pc);

            // Populate ITypeReader from event
            populate_i_type_reader(cols.adapter, event);
        }

        // Write to trace in column-major format
        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr riscv_addi_generate_trace_kernel() {
    return (KernelPtr)::riscv_addi_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
