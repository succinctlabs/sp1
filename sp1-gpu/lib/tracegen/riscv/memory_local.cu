/// GPU trace generation for RISC-V MemoryLocalChip.
///
/// MemoryLocalChip tracks local memory accesses within a shard (initial + final state).
/// Each row is completely independent - no sequential dependencies.

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

// Manually define SingleMemoryLocal that cbindgen can't resolve due to
// constant expression array sizes and Word type.
namespace sp1_gpu_sys {

template <typename T>
struct SingleMemoryLocal {
    T addr[3];
    T initial_clk_high;
    T final_clk_high;
    T initial_clk_low;
    T final_clk_low;
    Word<T> initial_value;
    Word<T> final_value;
    T initial_value_lower;
    T initial_value_upper;
    T final_value_lower;
    T final_value_upper;
    T is_real;
};

} // namespace sp1_gpu_sys

/// Main kernel for MemoryLocalChip trace generation.
///
/// Parameters:
///   trace: output trace buffer (column-major)
///   trace_height: padded height of the trace
///   events: array of MemoryLocalGpuEvent
///   nb_events: number of events
template <class T>
__global__ void riscv_memory_local_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::MemoryLocalGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::SingleMemoryLocal<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::SingleMemoryLocal<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            // Address as 3 x 16-bit limbs
            cols.addr[0] = T::from_canonical_u32((uint32_t)(event.addr & 0xFFFF));
            cols.addr[1] = T::from_canonical_u32((uint32_t)((event.addr >> 16) & 0xFFFF));
            cols.addr[2] = T::from_canonical_u32((uint32_t)((event.addr >> 32) & 0xFFFF));

            // Clock timestamps: high bits (>>24), low bits (&0xFFFFFF)
            cols.initial_clk_high =
                T::from_canonical_u32((uint32_t)(event.initial_timestamp >> 24));
            cols.final_clk_high = T::from_canonical_u32((uint32_t)(event.final_timestamp >> 24));
            cols.initial_clk_low =
                T::from_canonical_u32((uint32_t)(event.initial_timestamp & 0xFFFFFF));
            cols.final_clk_low =
                T::from_canonical_u32((uint32_t)(event.final_timestamp & 0xFFFFFF));

            // Initial and final values as Word (4 x 16-bit limbs)
            u64_to_word(event.initial_value, cols.initial_value);
            u64_to_word(event.final_value, cols.final_value);

            // Split third limb of initial value into 2 bytes (byte 4 and byte 5)
            cols.initial_value_lower =
                T::from_canonical_u32((uint32_t)((event.initial_value >> 32) & 0xFF));
            cols.initial_value_upper =
                T::from_canonical_u32((uint32_t)((event.initial_value >> 40) & 0xFF));

            // Split third limb of final value into 2 bytes (byte 4 and byte 5)
            cols.final_value_lower =
                T::from_canonical_u32((uint32_t)((event.final_value >> 32) & 0xFF));
            cols.final_value_upper =
                T::from_canonical_u32((uint32_t)((event.final_value >> 40) & 0xFF));

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
extern KernelPtr riscv_memory_local_generate_trace_kernel() {
    return (KernelPtr)::riscv_memory_local_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
