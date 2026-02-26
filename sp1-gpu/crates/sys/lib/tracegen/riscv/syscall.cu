/// GPU trace generation for RISC-V SyscallChip (Core and Precompile).

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

/// SyscallCols: 11 columns total.
template <class T>
struct SyscallCols {
    T clk_high;
    T clk_low;
    T syscall_id;
    T arg1[3];
    T arg2[3];
    T is_real;
};

/// Main kernel for SyscallChip trace generation.
template <class T>
__global__ void riscv_syscall_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::SyscallGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(SyscallCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        SyscallCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            // clk_high = top 8 bits (bits 24+)
            cols.clk_high = T::from_canonical_u32((uint32_t)(event.clk >> 24));
            // clk_low = lower 24 bits
            cols.clk_low = T::from_canonical_u32((uint32_t)(event.clk & 0xFFFFFF));

            // syscall_id
            cols.syscall_id = T::from_canonical_u32(event.syscall_id);

            // arg1: 3 x u16 limbs
            cols.arg1[0] = T::from_canonical_u32((uint32_t)(event.arg1 & 0xFFFF));
            cols.arg1[1] = T::from_canonical_u32((uint32_t)((event.arg1 >> 16) & 0xFFFF));
            cols.arg1[2] = T::from_canonical_u32((uint32_t)((event.arg1 >> 32) & 0xFFFF));

            // arg2: 3 x u16 limbs
            cols.arg2[0] = T::from_canonical_u32((uint32_t)(event.arg2 & 0xFFFF));
            cols.arg2[1] = T::from_canonical_u32((uint32_t)((event.arg2 >> 16) & 0xFFFF));
            cols.arg2[2] = T::from_canonical_u32((uint32_t)((event.arg2 >> 32) & 0xFFFF));

            cols.is_real = T::one();
        }

        // Write to trace in column-major format
        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr riscv_syscall_generate_trace_kernel() {
    return (KernelPtr)::riscv_syscall_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
