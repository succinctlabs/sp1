#include "tracegen/jagged_tracegen/tracegen.cuh"
#include "config.cuh"

__global__ void generateColIndex(
    uint32_t* col_index,
    uint32_t starting_cols,
    size_t trace_num_cols,
    size_t trace_num_rows) {

    size_t total = (trace_num_cols * trace_num_rows) >> 1;

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < total; i += blockDim.x * gridDim.x) {

        size_t col = i / (trace_num_rows >> 1);

        col_index[i] = col + starting_cols;
    }
}

__global__ void generateStartIndices(
    uint32_t* col_index,
    size_t offset,
    size_t trace_num_cols,
    size_t trace_num_rows) {
    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < trace_num_cols;
         i += blockDim.x * gridDim.x) {
        col_index[i] = (offset + i * trace_num_rows) >> 1;
    }
}

__global__ void fillBuffer(uint32_t* dst, uint32_t val, uint32_t max_log_row_count, size_t len) {

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < len; i += blockDim.x * gridDim.x) {
        dst[i] = val + i/(1 << (max_log_row_count-1));
    }
}

__global__ void countAndAddKernel(
    uint32_t* __restrict__ dst,
    felt_t*   __restrict__ src,
    size_t len
) {
    constexpr unsigned NUM_BINS = 320;
    __shared__ uint32_t counts[NUM_BINS];
    for (unsigned bin = threadIdx.x; bin < NUM_BINS; bin += blockDim.x)
        counts[bin] = 0;
    __syncthreads();

    for (size_t row = size_t(blockIdx.x) * blockDim.x + threadIdx.x; row < len;
         row += size_t(gridDim.x) * blockDim.x) {
        if (src[5 * len + row].as_canonical_u32() == 1) {
#pragma unroll
            for (unsigned col = 0; col < 4; ++col)
                atomicAdd(&counts[src[col * len + row].as_canonical_u32()], 1u);
            atomicAdd(&counts[256 + src[4 * len + row].as_canonical_u32()], 1u);
        }
    }
    __syncthreads();
    for (unsigned bin = threadIdx.x; bin < NUM_BINS; bin += blockDim.x) {
        if (counts[bin] != 0)
            atomicAdd(&dst[bin], counts[bin]);
    }
}

__global__ void sumToTraceKernel(
    felt_t* __restrict__ dst,
    uint32_t*   __restrict__ src
) {
    constexpr int NUM_BINS = 320;
    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < NUM_BINS;
         i += blockDim.x * gridDim.x) {
        if (i < 256) {
            dst[3 * (1 << 16) + i] += felt_t::from_canonical_u32(src[i]);
        } else {
            dst[4 * (1 << 16) + (i - 256) * (1 << 8) + 63] += felt_t::from_canonical_u32(src[i]);
        }
    }
}


extern "C" void* generate_col_index() { return (void*)generateColIndex; }
extern "C" void* generate_start_indices() { return (void*)generateStartIndices; }
extern "C" void* fill_buffer() { return (void*)fillBuffer; }
extern "C" void* count_and_add_kernel() { return (void*)countAndAddKernel; }
extern "C" void* sum_to_trace_kernel() { return (void*)sumToTraceKernel; }
