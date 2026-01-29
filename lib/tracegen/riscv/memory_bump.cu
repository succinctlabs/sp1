/// GPU trace generation for RISC-V MemoryBumpChip.
///
/// MemoryBumpChip bumps register memory timestamps to ensure monotonicity.
/// Each row is independent - no sequential dependencies.

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

// Manually define structs that cbindgen can't resolve.
namespace sp1_gpu_sys {

template <typename T>
struct MemoryAccessTimestampBump {
    T prev_high;
    T prev_low;
    T compare_low;
    T diff_low_limb;
    T diff_high_limb;
};

template <typename T>
struct MemoryAccessColsBump {
    Word<T> prev_value;
    MemoryAccessTimestampBump<T> access_timestamp;
};

template <typename T>
struct MemoryBumpCols {
    MemoryAccessColsBump<T> access;
    T clk_32_48;
    T clk_24_32;
    T clk_16_24;
    T clk_0_16;
    T addr;
    T is_real;
};

} // namespace sp1_gpu_sys

/// Populate MemoryAccessTimestamp for bump chip.
template <class T>
__device__ void populate_bump_memory_access_timestamp(
    sp1_gpu_sys::MemoryAccessTimestampBump<T>& ts,
    uint64_t prev_timestamp,
    uint64_t current_timestamp) {
    uint32_t prev_high = prev_timestamp >> 24;
    uint32_t prev_low_val = prev_timestamp & 0xFFFFFF;
    uint32_t current_high = current_timestamp >> 24;
    uint32_t current_low_val = current_timestamp & 0xFFFFFF;

    ts.prev_high = T::from_canonical_u32(prev_high);
    ts.prev_low = T::from_canonical_u32(prev_low_val);

    bool use_low_comparison = (prev_high == current_high);
    ts.compare_low = T::from_bool(use_low_comparison);

    uint32_t prev_time_value = use_low_comparison ? prev_low_val : prev_high;
    uint32_t current_time_value = use_low_comparison ? current_low_val : current_high;

    uint32_t diff_minus_one = current_time_value - prev_time_value - 1;
    ts.diff_low_limb = T::from_canonical_u32(diff_minus_one & 0xFFFF);
    ts.diff_high_limb = T::from_canonical_u32((diff_minus_one >> 16) & 0xFF);
}

/// Main kernel for MemoryBumpChip trace generation.
///
/// Parameters:
///   trace: output trace buffer (column-major)
///   trace_height: padded height of the trace
///   events: array of MemoryBumpGpuEvent
///   nb_events: number of events
template <class T>
__global__ void riscv_memory_bump_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::MemoryBumpGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::MemoryBumpCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::MemoryBumpCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            // Populate memory access columns (prev_value + timestamp)
            u64_to_word(event.prev_value, cols.access.prev_value);
            populate_bump_memory_access_timestamp(
                cols.access.access_timestamp,
                event.prev_timestamp,
                event.current_timestamp);

            // Timestamp decomposition
            cols.clk_0_16 = T::from_canonical_u32((uint32_t)(event.current_timestamp & 0xFFFF));
            cols.clk_16_24 =
                T::from_canonical_u32((uint32_t)((event.current_timestamp >> 16) & 0xFF));
            cols.clk_24_32 =
                T::from_canonical_u32((uint32_t)((event.current_timestamp >> 24) & 0xFF));
            cols.clk_32_48 =
                T::from_canonical_u32((uint32_t)((event.current_timestamp >> 32) & 0xFFFF));

            // Address and validity
            cols.addr = T::from_canonical_u32((uint32_t)(event.addr));
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
extern KernelPtr riscv_memory_bump_generate_trace_kernel() {
    return (KernelPtr)::riscv_memory_bump_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
