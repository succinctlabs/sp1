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
// Independent local scans. Totals are recursively scanned before applying offsets.
__global__ void curveScanLocal(bb31_septic_curve_t* output,
    const bb31_septic_curve_t* input, size_t n, bb31_septic_curve_t* totals) {
    constexpr unsigned SECTION = 512;
    __shared__ bb31_septic_curve_t aux[SECTION];
    unsigned t = threadIdx.x;
    size_t base = blockIdx.x * SECTION;
    aux[t] = base + t < n ? input[base + t] : bb31_septic_curve_t();
    aux[t + 256] = base + t + 256 < n ? input[base + t + 256] : bb31_septic_curve_t();
    for (unsigned stride = 1; stride <= 256; stride *= 2) {
        __syncthreads();
        unsigned i = (t + 1) * stride * 2 - 1;
        if (i < SECTION) aux[i] += aux[i - stride];
    }
    for (unsigned stride = 128; stride; stride /= 2) {
        __syncthreads();
        unsigned i = (t + 1) * stride * 2 - 1;
        if (i + stride < SECTION) aux[i + stride] += aux[i];
    }
    __syncthreads();
    if (base + t < n) output[base + t] = aux[t];
    if (base + t + 256 < n) output[base + t + 256] = aux[t + 256];
    if (t == 0) totals[blockIdx.x] = aux[SECTION - 1];
}

__global__ void curveScanOffsets(bb31_septic_curve_t* output,
    const bb31_septic_curve_t* totals, size_t n) {
    size_t block = blockIdx.x + 1;
    bb31_septic_curve_t offset = totals[block - 1];
    size_t i = block * 512 + threadIdx.x;
    if (i < n) output[i] += offset;
    if (i + 256 < n) output[i + 256] += offset;
}

namespace sp1_gpu_sys {
extern KernelPtr curve_scan_local_kernel() { return (KernelPtr)curveScanLocal; }
extern KernelPtr curve_scan_offsets_kernel() { return (KernelPtr)curveScanOffsets; }
}
