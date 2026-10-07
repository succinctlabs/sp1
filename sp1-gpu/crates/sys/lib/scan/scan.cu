#include "sp1-gpu-cbindgen.hpp"
#include "scan/scan.cuh"
#include "fields/kb31_septic_extension_t.cuh"

namespace sp1_gpu_sys {
extern KernelPtr single_block_scan_kernel_large_bb31_septic_curve() {
    return (KernelPtr)scan_large::SingleBlockScan<bb31_septic_curve_t>;
}
extern KernelPtr scan_kernel_large_bb31_septic_curve() {
    return (KernelPtr)scan_large::Scan<bb31_septic_curve_t>;
}
} // namespace sp1_gpu_sys
// Each thread scans two points; keep these in sync with tracegen/src/riscv/global.rs.
constexpr unsigned CURVE_SCAN_BLOCK_SIZE = 256;
constexpr unsigned CURVE_SCAN_POINTS_PER_BLOCK = 2 * CURVE_SCAN_BLOCK_SIZE;

// Independent local scans. Totals are recursively scanned before applying offsets.
__global__ void curveScanLocal(bb31_septic_curve_t* output,
    const bb31_septic_curve_t* input, size_t n, bb31_septic_curve_t* totals) {
    __shared__ bb31_septic_curve_t aux[CURVE_SCAN_POINTS_PER_BLOCK];
    unsigned t = threadIdx.x;
    size_t base = blockIdx.x * CURVE_SCAN_POINTS_PER_BLOCK;
    aux[t] = base + t < n ? input[base + t] : bb31_septic_curve_t();
    aux[t + CURVE_SCAN_BLOCK_SIZE] = base + t + CURVE_SCAN_BLOCK_SIZE < n
        ? input[base + t + CURVE_SCAN_BLOCK_SIZE] : bb31_septic_curve_t();
    for (unsigned stride = 1; stride <= CURVE_SCAN_BLOCK_SIZE; stride *= 2) {
        __syncthreads();
        unsigned i = (t + 1) * stride * 2 - 1;
        if (i < CURVE_SCAN_POINTS_PER_BLOCK) aux[i] += aux[i - stride];
    }
    for (unsigned stride = CURVE_SCAN_BLOCK_SIZE / 2; stride; stride /= 2) {
        __syncthreads();
        unsigned i = (t + 1) * stride * 2 - 1;
        if (i + stride < CURVE_SCAN_POINTS_PER_BLOCK) aux[i + stride] += aux[i];
    }
    __syncthreads();
    if (base + t < n) output[base + t] = aux[t];
    if (base + t + CURVE_SCAN_BLOCK_SIZE < n)
        output[base + t + CURVE_SCAN_BLOCK_SIZE] = aux[t + CURVE_SCAN_BLOCK_SIZE];
    if (t == 0) totals[blockIdx.x] = aux[CURVE_SCAN_POINTS_PER_BLOCK - 1];
}

__global__ void curveScanOffsets(bb31_septic_curve_t* output,
    const bb31_septic_curve_t* totals, size_t n) {
    size_t block = blockIdx.x + 1;
    bb31_septic_curve_t offset = totals[block - 1];
    size_t i = block * CURVE_SCAN_POINTS_PER_BLOCK + threadIdx.x;
    if (i < n) output[i] += offset;
    if (i + CURVE_SCAN_BLOCK_SIZE < n) output[i + CURVE_SCAN_BLOCK_SIZE] += offset;
}

namespace sp1_gpu_sys {
extern KernelPtr curve_scan_local_kernel() { return (KernelPtr)curveScanLocal; }
extern KernelPtr curve_scan_offsets_kernel() { return (KernelPtr)curveScanOffsets; }
}
