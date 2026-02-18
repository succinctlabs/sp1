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
    constexpr int NUM_BINS = 320;
    constexpr int THREADS_PER_BLOCK = 16;

    __shared__ unsigned int s_hist[THREADS_PER_BLOCK][NUM_BINS];

    const int tid = threadIdx.x;

    for (int bin = 0; bin < NUM_BINS; ++bin) {
        s_hist[tid][bin] = 0;
    }
    __syncthreads();

    const size_t total_threads = blockDim.x * gridDim.x;
    size_t idx = blockIdx.x * blockDim.x + tid;

    while (idx < len) {
        uint32_t is_real = src[5 * len + idx].as_canonical_u32();
        if (is_real == 1) {
            uint32_t v = src[idx].as_canonical_u32();
            s_hist[tid][v] += 1;
            v = src[len + idx].as_canonical_u32();
            s_hist[tid][v] += 1;
            v = src[2 * len + idx].as_canonical_u32();
            s_hist[tid][v] += 1;
            v = src[3 * len + idx].as_canonical_u32();
            s_hist[tid][v] += 1;
            v = src[4 * len + idx].as_canonical_u32();
            s_hist[tid][v + 256] += 1;
        }
        idx += total_threads;
    }
    __syncthreads();

    for (int stride = THREADS_PER_BLOCK / 2; stride > 0; stride >>= 1) {
        if (tid < stride) {
            for (int bin = 0; bin < NUM_BINS; ++bin) {
                s_hist[tid][bin] += s_hist[tid + stride][bin];
            }
        }
        __syncthreads();
    }

    if (tid == 0) {
        for (int bin = 0; bin < NUM_BINS; ++bin) {
            unsigned int c = s_hist[0][bin];
            if (c != 0) {
                atomicAdd(&dst[bin], c);
            }
        }
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
