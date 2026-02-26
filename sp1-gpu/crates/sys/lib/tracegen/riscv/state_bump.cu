/// GPU trace generation for RISC-V StateBumpChip.
///
/// StateBumpChip bumps CPU state (clock and program counter).
/// Each row is independent - no sequential dependencies.

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

// PC_INC constant (same as sp1_core_executor::PC_INC).
static const uint32_t PC_INC = 4;

// Manually define StateBumpCols.
namespace sp1_gpu_sys {

template <typename T>
struct StateBumpCols {
    T next_clk_32_48;
    T next_clk_24_32;
    T next_clk_16_24;
    T next_clk_0_16;
    T clk_high;
    T clk_low;
    T next_pc[3];
    T pc[3];
    T is_clk;
    T is_real;
};

} // namespace sp1_gpu_sys

/// Main kernel for StateBumpChip trace generation.
///
/// Parameters:
///   trace: output trace buffer (column-major)
///   trace_height: padded height of the trace
///   events: array of StateBumpGpuEvent
///   nb_events: number of events
template <class T>
__global__ void riscv_state_bump_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::StateBumpGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::StateBumpCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::StateBumpCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            uint64_t clk = event.clk;
            uint64_t increment = event.increment;
            bool bump2 = (event.bump2 != 0);
            uint64_t pc = event.pc;

            // clk_low = (clk & 0xFFFFFF) + increment
            uint32_t clk_low = (uint32_t)((clk & 0xFFFFFF) + increment);
            uint32_t clk_high = (uint32_t)(clk >> 24);

            // next_clk = clk + increment
            uint64_t next_clk = clk + increment;
            uint16_t next_clk_0_16 = (uint16_t)(next_clk & 0xFFFF);
            uint8_t next_clk_16_24 = (uint8_t)((next_clk >> 16) & 0xFF);
            uint8_t next_clk_24_32 = (uint8_t)((next_clk >> 24) & 0xFF);
            uint16_t next_clk_32_48 = (uint16_t)(next_clk >> 32);

            cols.clk_low = T::from_canonical_u32(clk_low);
            cols.clk_high = T::from_canonical_u32(clk_high);
            cols.next_clk_0_16 = T::from_canonical_u32(next_clk_0_16);
            cols.next_clk_16_24 = T::from_canonical_u32(next_clk_16_24);
            cols.next_clk_24_32 = T::from_canonical_u32(next_clk_24_32);
            cols.next_clk_32_48 = T::from_canonical_u32(next_clk_32_48);

            // next_pc = pc as 3 u16 limbs
            cols.next_pc[0] = T::from_canonical_u32((uint32_t)(pc & 0xFFFF));
            cols.next_pc[1] = T::from_canonical_u32((uint32_t)((pc >> 16) & 0xFFFF));
            cols.next_pc[2] = T::from_canonical_u32((uint32_t)((pc >> 32) & 0xFFFF));

            if (bump2) {
                // When bump2, pc[0] = prev_pc_limb0 + PC_INC, pc[1..2] = prev_pc_limb1..2
                uint64_t prev_pc = pc - PC_INC;
                cols.pc[0] = T::from_canonical_u32((uint32_t)(prev_pc & 0xFFFF)) +
                             T::from_canonical_u32(PC_INC);
                cols.pc[1] = T::from_canonical_u32((uint32_t)((prev_pc >> 16) & 0xFFFF));
                cols.pc[2] = T::from_canonical_u32((uint32_t)((prev_pc >> 32) & 0xFFFF));
            } else {
                // When not bump2, pc = next_pc
                cols.pc[0] = cols.next_pc[0];
                cols.pc[1] = cols.next_pc[1];
                cols.pc[2] = cols.next_pc[2];
            }

            // is_clk: carry from low to high part of clock
            if ((next_clk >> 24) != (clk >> 24)) {
                cols.is_clk = T::one();
            }

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
extern KernelPtr riscv_state_bump_generate_trace_kernel() {
    return (KernelPtr)::riscv_state_bump_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
