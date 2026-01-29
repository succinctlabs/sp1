/// GPU trace generation for RISC-V lookup table chips (ByteChip, RangeChip).
///
/// These chips use a scatter-write pattern: the trace is mostly zeros,
/// and we write multiplicities at specific (row, column) positions derived
/// from a HashMap of byte lookup entries.

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

// ByteChip: 6 multiplicity columns, 65536 rows (1 << 16)
static const size_t BYTE_NUM_COLS = 6;

// RangeChip: 1 multiplicity column, 131072 rows (1 << 17)
static const size_t RANGE_NUM_COLS = 1;

/// ByteChip scatter kernel.
///
/// Each thread processes one entry from the flattened HashMap.
/// Writes trace[row + opcode * trace_height] = from_canonical_u32(mult).
template <class T>
__global__ void riscv_byte_lookup_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::ByteLookupGpuEntry* entries,
    uintptr_t nb_entries) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        if (i < nb_entries) {
            const auto& entry = entries[i];
            uint32_t row = entry.row;
            uint32_t col = entry.opcode;
            T mult = T::from_canonical_u32(entry.mult);
            trace[row + col * trace_height] = mult;
        }
        // Rows beyond nb_entries are already zero-initialized by Tensor::zeros_in
    }
}

/// RangeChip scatter kernel.
///
/// Each thread processes one entry from the flattened HashMap.
/// Writes trace[row] = from_canonical_u32(mult).
/// Since RangeChip has only 1 column, no column offset needed.
template <class T>
__global__ void riscv_range_lookup_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::RangeLookupGpuEntry* entries,
    uintptr_t nb_entries) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        if (i < nb_entries) {
            const auto& entry = entries[i];
            uint32_t row = entry.row;
            T mult = T::from_canonical_u32(entry.mult);
            trace[row] = mult;
        }
        // Rows beyond nb_entries are already zero-initialized by Tensor::zeros_in
    }
}

namespace sp1_gpu_sys {

extern KernelPtr riscv_byte_lookup_generate_trace_kernel() {
    return (KernelPtr)::riscv_byte_lookup_generate_trace_kernel<kb31_t>;
}

extern KernelPtr riscv_range_lookup_generate_trace_kernel() {
    return (KernelPtr)::riscv_range_lookup_generate_trace_kernel<kb31_t>;
}

} // namespace sp1_gpu_sys
