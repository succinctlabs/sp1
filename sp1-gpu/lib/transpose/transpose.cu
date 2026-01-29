#include "transpose/transpose.cuh"
#include "fields/kb31_t.cuh"
#include "fields/kb31_extension_t.cuh"

namespace transpose {
template <typename T>
__global__ void transpose_kernel(
    const T* __restrict__ in,
    T* __restrict__ out,
    size_t dimX,
    size_t dimY,
    size_t dimZ) {
    size_t startX = blockIdx.x * blockDim.x + threadIdx.x;
    size_t startY = blockIdx.y * blockDim.y + threadIdx.y;
    size_t gridStrideX = blockDim.x * gridDim.x;
    size_t gridStrideY = blockDim.y * gridDim.y;
    size_t startZ = blockIdx.z * blockDim.z + threadIdx.z;
    size_t gridStrideZ = blockDim.z * gridDim.z;

    for (size_t idxX = startX; idxX < dimX; idxX += gridStrideX) {
        for (size_t idxY = startY; idxY < dimY; idxY += gridStrideY) {
            for (size_t idxZ = startZ; idxZ < dimZ; idxZ += gridStrideZ) {
                out[idxZ * dimX * dimY + idxY * dimX + idxX] =
                    in[idxZ * dimX * dimY + idxX * dimY + idxY];
            }
        }
    }
}

template <typename T, int N>
__global__ void transpose_array_kernel(
    T (*__restrict__ in)[N],
    T (*__restrict__ out)[N],
    size_t dimX,
    size_t dimY,
    size_t dimZ) {
    size_t startX = blockIdx.x * blockDim.x + threadIdx.x;
    size_t startY = blockIdx.y * blockDim.y + threadIdx.y;
    size_t gridStrideX = blockDim.y * gridDim.y;
    size_t gridStrideY = blockDim.x * gridDim.x;
    size_t startZ = blockIdx.z * blockDim.z + threadIdx.z;
    size_t gridStrideZ = blockDim.z * gridDim.z;

    for (size_t idxX = startX; idxX < dimX; idxX += gridStrideX) {
        for (size_t idxY = startY; idxY < dimY; idxY += gridStrideY) {
            for (size_t idxZ = startZ; idxZ < dimZ; idxZ += gridStrideZ) {
                T* out_ptr = out[idxZ * dimX * dimY + idxX * dimY + idxY];
                T* in_ptr = in[idxZ * dimX * dimY + idxY * dimX + idxX];
#pragma unroll
                for (int i = 0; i < N; i++) {
                    out_ptr[i] = in_ptr[i];
                }
            }
        }
    }
}

extern "C" void* transpose_kernel_koala_bear() { return (void*)transpose_kernel<kb31_t>; }

extern "C" void* transpose_kernel_koala_bear_digest() {
    return (void*)transpose_array_kernel<kb31_t, 8>;
}

extern "C" void* transpose_kernel_u32() { return (void*)transpose_kernel<uint32_t>; }

extern "C" void* transpose_kernel_u32_digest() {
    return (void*)transpose_array_kernel<uint32_t, 8>;
}

extern "C" void* transpose_kernel_koala_bear_extension() {
    return (void*)transpose_kernel<kb31_extension_t>;
}

// #define TILE_DIM 32
// #define BLOCK_ROWS 16

//     template <typename T>
//     __global__ void transpose_kernel_tiled(
//         const T *__restrict__ in,
//         T *__restrict__ out,
//         size_t rows,
//         size_t cols)
//     {
//         // Shared memory tile
//         __shared__ T tile[TILE_DIM][TILE_DIM + 1];

//         // Loop over tiles in the row dimension (grid-stride)
//         for (int tileStartRow = blockIdx.y * TILE_DIM;
//              tileStartRow < rows;
//              tileStartRow += gridDim.y * TILE_DIM)
//         {
//             // Loop over tiles in the column dimension (grid-stride)
//             for (int tileStartCol = blockIdx.x * TILE_DIM;
//                  tileStartCol < cols;
//                  tileStartCol += gridDim.x * TILE_DIM)
//             {
//                 // Compute the global row/col for this thread within the tile
//                 size_t row = tileStartRow + threadIdx.y;
//                 size_t col = tileStartCol + threadIdx.x;

//                 // Read data from global memory into shared memory
//                 if (row < rows && col < cols)
//                 {
//                     tile[threadIdx.y][threadIdx.x] = in[row * cols + col];
//                 }
//                 __syncthreads();

//                 // Compute transposed location
//                 // Now each thread writes the transposed element from shared memory
//                 size_t transposedRow = tileStartCol + threadIdx.y;
//                 size_t transposedCol = tileStartRow + threadIdx.x;
//                 if (transposedRow < cols && transposedCol < rows)
//                 {
//                     out[transposedRow * rows + transposedCol] =
//                         tile[threadIdx.x][threadIdx.y];
//                 }
//                 __syncthreads();
//             }
//         }
//     }

//     extern "C" void *transpose_kernel_tiled_koala_bear()
//     {
//         return (void *)transpose_kernel_tiled<kb31_t>;
//     }

} // namespace transpose