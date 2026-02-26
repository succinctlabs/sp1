/// GPU trace generation for RISC-V MemoryGlobalChip (Init and Finalize).
///
/// MemoryGlobalChip proves that memory addresses are strictly increasing.
/// Events must be sorted by address before being sent to the GPU.

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

// Manually define types that cbindgen can't resolve due to constant
// expression array sizes like [T; WORD_SIZE].
namespace sp1_gpu_sys {

template <typename T>
struct U16CompareOperation {
    T bit;
};

template <typename T>
struct LtOperationUnsigned {
    U16CompareOperation<T> u16_compare_operation;
    T u16_flags[WORD_SIZE];
    T not_eq_inv;
    T comparison_limbs[2];
};

template <typename T>
struct IsZeroOperation {
    T inverse;
    T result;
};

template <typename T>
struct MemoryInitCols {
    T clk_high;
    T clk_low;
    T index;
    T prev_addr[3];
    T addr[3];
    LtOperationUnsigned<T> lt_cols;
    Word<T> value;
    T value_lower;
    T value_upper;
    T is_real;
    T is_comp;
    T prev_valid;
    IsZeroOperation<T> is_prev_addr_zero;
    IsZeroOperation<T> is_index_zero;
};

} // namespace sp1_gpu_sys

/// Extract u16 limbs from a u64 value.
__device__ void u64_to_u16_limbs_mg(uint64_t value, uint16_t limbs[WORD_SIZE]) {
    limbs[0] = value & 0xFFFF;
    limbs[1] = (value >> 16) & 0xFFFF;
    limbs[2] = (value >> 32) & 0xFFFF;
    limbs[3] = (value >> 48) & 0xFFFF;
}

/// Populate LtOperationUnsigned for address comparison (prev_addr < addr).
/// a_u64 is the expected comparison result (always 1 for strictly increasing).
template <class T>
__device__ void populate_lt_unsigned(
    sp1_gpu_sys::LtOperationUnsigned<T>& op,
    uint64_t a_u64,
    uint64_t b_u64,
    uint64_t c_u64) {
    // Initialize all fields to zero
    op.u16_compare_operation.bit = T::zero();
    for (int i = 0; i < WORD_SIZE; i++) {
        op.u16_flags[i] = T::zero();
    }
    op.not_eq_inv = T::zero();
    op.comparison_limbs[0] = T::zero();
    op.comparison_limbs[1] = T::zero();

    uint16_t b_limbs[WORD_SIZE];
    uint16_t c_limbs[WORD_SIZE];
    u64_to_u16_limbs_mg(b_u64, b_limbs);
    u64_to_u16_limbs_mg(c_u64, c_limbs);

    // Find the most significant differing limb (iterate from high to low)
    for (int i = WORD_SIZE - 1; i >= 0; i--) {
        if (b_limbs[i] != c_limbs[i]) {
            op.u16_flags[i] = T::one();
            op.comparison_limbs[0] = T::from_canonical_u32(b_limbs[i]);
            op.comparison_limbs[1] = T::from_canonical_u32(c_limbs[i]);

            // Compute inverse of (b_limb - c_limb) in the field
            T b_field = T::from_canonical_u32(b_limbs[i]);
            T c_field = T::from_canonical_u32(c_limbs[i]);
            T diff = b_field - c_field;
            op.not_eq_inv = diff.reciprocal();
            break;
        }
    }

    // The comparison result bit (a_u64 is always 1 when prev_addr < addr)
    op.u16_compare_operation.bit = T::from_canonical_u32((uint32_t)(a_u64 & 1));
}

/// Populate IsZeroOperation from a field element value.
template <class T>
__device__ void populate_is_zero_from_field(sp1_gpu_sys::IsZeroOperation<T>& op, T a) {
    if (a == T::zero()) {
        op.inverse = T::zero();
        op.result = T::one();
    } else {
        op.inverse = a.reciprocal();
        op.result = T::zero();
    }
}

/// Populate IsZeroOperation from a u64 value.
template <class T>
__device__ void populate_is_zero(sp1_gpu_sys::IsZeroOperation<T>& op, uint64_t a) {
    populate_is_zero_from_field(op, T::from_canonical_u32((uint32_t)(a & 0xFFFFFFFF)));
}

/// Main kernel for MemoryGlobalChip trace generation.
///
/// Parameters:
///   trace: output trace buffer (column-major)
///   trace_height: padded height of the trace
///   events: sorted array of MemoryGlobalGpuEvent
///   nb_events: number of events
///   previous_addr: the address from the previous shard (for row 0's prev_addr)
template <class T>
__global__ void riscv_memory_global_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::MemoryGlobalGpuEvent* events,
    uintptr_t nb_events,
    uint64_t previous_addr) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::MemoryInitCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::MemoryInitCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            // Populate basic fields (Phase 1 - parallel)
            cols.addr[0] = T::from_canonical_u32((uint32_t)(event.addr & 0xFFFF));
            cols.addr[1] = T::from_canonical_u32((uint32_t)((event.addr >> 16) & 0xFFFF));
            cols.addr[2] = T::from_canonical_u32((uint32_t)((event.addr >> 32) & 0xFFFF));

            cols.clk_high = T::from_canonical_u32((uint32_t)(event.timestamp >> 24));
            cols.clk_low = T::from_canonical_u32((uint32_t)(event.timestamp & 0xFFFFFF));

            u64_to_word(event.value, cols.value);
            cols.is_real = T::one();
            cols.value_lower = T::from_canonical_u32((uint32_t)((event.value >> 32) & 0xFF));
            cols.value_upper = T::from_canonical_u32((uint32_t)((event.value >> 40) & 0xFF));

            // Populate dependent fields (Phase 2)
            uint64_t prev_addr = (i == 0) ? previous_addr : events[i - 1].addr;

            // prev_valid: zero only when prev_addr == 0 AND i != 0
            if (prev_addr == 0 && i != 0) {
                cols.prev_valid = T::zero();
            } else {
                cols.prev_valid = T::one();
            }

            // index
            cols.index = T::from_canonical_u32((uint32_t)i);

            // prev_addr
            cols.prev_addr[0] = T::from_canonical_u32((uint32_t)(prev_addr & 0xFFFF));
            cols.prev_addr[1] = T::from_canonical_u32((uint32_t)((prev_addr >> 16) & 0xFFFF));
            cols.prev_addr[2] = T::from_canonical_u32((uint32_t)((prev_addr >> 32) & 0xFFFF));

            // is_prev_addr_zero: IsZero of (prev_addr[0] + prev_addr[1] + prev_addr[2])
            T prev_addr_sum = cols.prev_addr[0] + cols.prev_addr[1] + cols.prev_addr[2];
            populate_is_zero_from_field(cols.is_prev_addr_zero, prev_addr_sum);

            // is_index_zero: IsZero of index
            populate_is_zero(cols.is_index_zero, (uint64_t)i);

            // is_comp and lt_cols
            if (prev_addr != 0 || i != 0) {
                cols.is_comp = T::one();
                populate_lt_unsigned(cols.lt_cols, 1ULL, prev_addr, event.addr);
            } else {
                cols.is_comp = T::zero();
                // lt_cols already zero-initialized
            }
        }

        // Write to trace in column-major format
        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr riscv_memory_global_generate_trace_kernel() {
    return (KernelPtr)::riscv_memory_global_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
