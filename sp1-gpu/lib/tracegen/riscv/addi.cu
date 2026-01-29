/// GPU trace generation for RISC-V AddiChip.

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

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
