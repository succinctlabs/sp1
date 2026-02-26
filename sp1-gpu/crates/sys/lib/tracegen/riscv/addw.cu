/// GPU trace generation for RISC-V AddwChip.

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

// Manually define AddwOperation since cbindgen can't handle WORD_SIZE / 2 constant expression.
// This matches the Rust struct: value: [T; WORD_SIZE / 2] (i.e., [T; 2]) and msb:
// U16MSBOperation<T>
namespace sp1_gpu_sys {
template <typename T>
struct AddwOperation {
    /// The result of the ADDW operation (2 x u16 limbs).
    T value[2];
    /// The msb of the result.
    U16MSBOperation<T> msb;
};
} // namespace sp1_gpu_sys

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
