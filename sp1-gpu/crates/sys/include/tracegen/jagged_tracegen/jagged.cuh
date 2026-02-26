#pragma once
#include "config.cuh"
#include <stdint.h>
#include "sum_and_reduce/reduce.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

// Upper_bound for monotone start_idx (returns first j with start_idx[j] > x)
__device__ __forceinline__ uint32_t
upper_bound_u32(const uint32_t* __restrict__ a, uint32_t n, uint32_t x) {
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = (lo + hi) >> 1;
        uint32_t v = a[mid];
        if (v <= x)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo; // in [0..n]
}

/// A jagged MLE : a concatenation of a bunch of columns of varying length.
template <typename DenseData>
struct JaggedMle {
    using OutputDenseData = typename DenseData::OutputDenseData;

  public:
    /// Has length(q) / 2. colIndex[i] is the column that q[i] belongs to.
    uint32_t* colIndex;
    /// Has length one more than the number of columns. startIndices[i] * 2 is the start index of
    /// the i-th column in q[i].
    uint32_t* startIndices;
    /// A contiguous vector of dense underlying data
    DenseData denseData;

    // i is between 0 and length(colIndex)
    __forceinline__ __device__ size_t
    fixLastVariableUnchecked(JaggedMle<OutputDenseData>& output, size_t i, ext_t alpha) const {
        size_t colIdx = this->colIndex[i];
        size_t startIdx = this->startIndices[colIdx];
        size_t interactionHeight = this->startIndices[colIdx + 1] - startIdx;

        size_t rowIdx = i - startIdx;

        size_t zeroIdx = i << 1;
        size_t oneIdx = (i << 1) + 1;
        size_t restrictedIndex = (output.startIndices[colIdx] << 1) + rowIdx;

        this->denseData.fixLastVariable(output.denseData, restrictedIndex, zeroIdx, oneIdx, alpha);

        return restrictedIndex;
    }

    // i is between 0 and length(colIndex). Assumes that length(colIndex) is even.
    __forceinline__ __device__ size_t
    fixLastVariableTwoPadding(JaggedMle<OutputDenseData>& output, size_t i, ext_t alpha) const {
        // The current column
        size_t colIdx = this->colIndex[i];
        size_t startIdx = this->startIndices[colIdx];
        size_t interactionHeight = this->startIndices[colIdx + 1] - startIdx;

        // The current location within the column
        size_t rowIdx = i - startIdx;

        size_t zeroIdx = i << 1;
        size_t oneIdx = (i << 1) + 1;
        size_t restrictedIndex = (output.startIndices[colIdx] << 1) + rowIdx;

        this->denseData.fixLastVariable(output.denseData, restrictedIndex, zeroIdx, oneIdx, alpha);

        // If this column does not have a length that is a multiple of four, the next column will
        // have an odd length. So we need to add some extra padding to the next column.
        size_t remainderModFour = interactionHeight & 3;
        bool isLast = (interactionHeight - 1) == rowIdx;
        if (remainderModFour && isLast) {
            this->denseData.pad(output.denseData, restrictedIndex + 1);
            this->denseData.pad(output.denseData, restrictedIndex + 2);

            // We also need to update the output colIndex.
            output.colIndex[(restrictedIndex >> 1) + 1] = colIdx;
        }

        if (rowIdx & 1) {
            output.colIndex[restrictedIndex >> 1] = colIdx;
        }

        return restrictedIndex;
    }

    __forceinline__ __device__ size_t
    fixLastVariableTwoPaddingInfo(JaggedMle<OutputDenseData>& output, size_t i) const {
        size_t colIdx = this->colIndex[i];
        size_t startIdx = this->startIndices[colIdx];
        size_t interactionHeight = this->startIndices[colIdx + 1] - startIdx;

        size_t rowIdx = i - startIdx;

        size_t zeroIdx = i << 1;
        size_t restrictedIndex = (output.startIndices[colIdx] << 1) + rowIdx;

        uint32_t info = this->denseData.fixLastVariable(output.denseData, restrictedIndex, zeroIdx);

        // If this row does not have a length that is a multiple of four, the next row will have an
        // odd length. So we need to add some extra padding to the next row.
        size_t remainderModFour = interactionHeight & 3;
        bool isLast = (interactionHeight - 1) == rowIdx;
        if (remainderModFour && isLast) {
            this->denseData.pad_const(output.denseData, restrictedIndex + 1, info);
            this->denseData.pad_const(output.denseData, restrictedIndex + 2, info);

            // We also need to update the outputcolIndex.
            output.colIndex[(restrictedIndex >> 1) + 1] = colIdx;
        }

        if (rowIdx & 1) {
            output.colIndex[restrictedIndex >> 1] = colIdx;
        }

        return restrictedIndex;
    }

    __device__ void evaluate(
        const ext_t* __restrict__ row_coefficient,
        const ext_t* __restrict__ col_coefficient,
        uint32_t L,
        uint32_t num_cols,
        ext_t* __restrict__ output_evals) const {
        const uint32_t CHUNK_ELEMS = 1 << 15;
        const uint32_t MAX_COLS_SH = 16;

        const uint32_t chunk_id = blockIdx.x;
        // [g0, g1) is the range of the chunk this block handles
        const uint32_t g0 = chunk_id * uint32_t(CHUNK_ELEMS);
        if (g0 >= L)
            return;
        const uint32_t g1 = min(L, g0 + uint32_t(CHUNK_ELEMS));

        // Find which columns this chunk touches by binary search: [c0, c1] is the range.
        const uint32_t c0 = upper_bound_u32(this->startIndices, num_cols + 1, g0) - 1;
        const uint32_t c1 = upper_bound_u32(this->startIndices, num_cols + 1, g1 - 1) - 1;
        const uint32_t kcols = c1 - c0 + 1;

        // Shared memory layout:
        // ext_t `nwarps` (for ext_t reduction)
        // uint32_t `MAX_COLS_SH + 1` (for loading startIndices)
        // ext_t `MAX_COLS_SH` (for loading col_coefficient)
        extern __shared__ __align__(16) unsigned char smem_raw[];
        const int nwarps = blockDim.x / 32;
        ext_t* sh_reduce = reinterpret_cast<ext_t*>(smem_raw);
        uint32_t* sh_start = reinterpret_cast<uint32_t*>(sh_reduce + nwarps);
        ext_t* sh_zcol = reinterpret_cast<ext_t*>(sh_start + (MAX_COLS_SH + 1));

        // Only use shared if number of columns within the chunk is not large.
        const bool use_shared = (kcols <= MAX_COLS_SH);

        // Load in all the required `start_idx` and `col_coefficient` values for the chunk.
        if (use_shared) {
            for (uint32_t t = threadIdx.x; t <= kcols; t += blockDim.x) {
                sh_start[t] = this->startIndices[c0 + t];
            }
            for (uint32_t t = threadIdx.x; t < kcols; t += blockDim.x) {
                sh_zcol[t] = col_coefficient[c0 + t];
            }
            __syncthreads();
        }

        // Per-thread sweeping state
        ext_t acc = ext_t::zero();

        // Starting index of the current thread.
        uint32_t i = g0 + threadIdx.x;

        // Current column is `c`, with range of indices `[start_c, end_c)`.
        // The corresponding `col_coefficient` value is `zc`.
        uint32_t c = 0, start_c = 0, end_c = 0;
        ext_t zc = ext_t::zero();
        ext_t cur_acc = ext_t::zero();

        if (i < g1) {
            if (use_shared) {
                // Binary search in shared starts to get initial column.
                uint32_t lo = 0, hi = kcols;
                while (lo < hi) {
                    uint32_t mid = (lo + hi + 1) >> 1;
                    if (sh_start[mid] <= i)
                        lo = mid;
                    else
                        hi = mid - 1;
                }
                c = c0 + lo;
                start_c = sh_start[lo];
                end_c = sh_start[lo + 1];
                zc = sh_zcol[lo];
            } else {
                c = upper_bound_u32(this->startIndices, num_cols + 1, i) - 1;
                start_c = this->startIndices[c];
                end_c = this->startIndices[c + 1];
                zc = col_coefficient[c];
            }
        }

        // Each thread strides by blockDim.x.
        for (; i < g1; i += blockDim.x) {
            // Advance the columns if we crossed the boundary.
            // This can cross multiple if the columns are tiny.
            if (i >= end_c) {
                acc += cur_acc * zc;
                cur_acc = ext_t::zero();
            }
            while (i >= end_c) {
                c += 1;
                start_c = end_c;
                if (use_shared) {
                    const uint32_t t = c - c0;
                    end_c = sh_start[t + 1];
                    zc = sh_zcol[t];
                } else {
                    end_c = this->startIndices[c + 1];
                    zc = col_coefficient[c];
                }
            }
            const uint32_t row = i - start_c;
            ext_t row_coefficient_0 = row_coefficient[row << 1];
            ext_t row_coefficient_1 = row_coefficient[row << 1 | 1];
            cur_acc += this->denseData.evaluate(i << 1, row_coefficient_0);
            cur_acc += this->denseData.evaluate(i << 1 | 1, row_coefficient_1);
        }
        acc += cur_acc * zc;

        auto block = cg::this_thread_block();
        auto tile = cg::tiled_partition<32>(block);
        ext_t block_sum = partialBlockReduce(block, tile, acc, sh_reduce);

        if (threadIdx.x == 0) {
            ext_t::store(output_evals, blockIdx.x, block_sum);
        }
    }
};
