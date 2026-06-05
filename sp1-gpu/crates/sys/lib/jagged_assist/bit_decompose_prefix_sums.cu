#include "jagged_assist/bit_decompose_prefix_sums.cuh"
#include "fields/kb31_t.cuh"

#include <cstdint>

// Constants must match `slop_jagged::jagged_assist::two_stage_jagged::{K, PREFIX_SUM_BITS}`.
namespace {
constexpr uint32_t K = 64;
constexpr uint32_t PREFIX_SUM_BITS = 32;
}

// Bit-decompose interleaved prefix sums into a [K, two_c] Felt MLE.
//
// Inputs:
//   prefix_sums:    device buffer of length `num_real_pairs + 1` of packed
//                   u32 prefix sums.
//   num_real_pairs: number of real (curr, next) column pairs.  Columns >=
//                   num_real_pairs are zero-padded.
//   two_c:          stride and total column count, must be a power of two
//                   and >= num_real_pairs.
//   out:            device output buffer of length `K * two_c` (Felts).
//                   Layout mirrors `build_merged_bit_mle_flat_gpu_layout`:
//                   `out[k * two_c + col]` is bit `k`'s value at column
//                   `col` of the interleaved bit-MLE.
//
// Mapping `k -> (bit, source)` (mirrors the host build):
//   b        = PREFIX_SUM_BITS - 1 - (k >> 1)        // 0 = LSB, 31 = MSB
//   is_curr  = (k & 1) == 1                          // odd k -> curr, even -> next
//   src      = is_curr ? prefix_sums[col] : prefix_sums[col + 1]
//   out_bit  = (src >> b) & 1
//
// Grid: 2D, x = columns, y = bit rows.  Each thread writes one cell.
template<typename F>
__global__ void bitDecomposePrefixSums(
    const uint32_t *__restrict__ prefix_sums,
    uint32_t num_real_pairs,
    uint32_t two_c,
    F *__restrict__ out)
{
    uint32_t col = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t k   = blockIdx.y * blockDim.y + threadIdx.y;
    if (col >= two_c || k >= K) return;

    F val = F::zero();
    if (col < num_real_pairs) {
        uint32_t b = PREFIX_SUM_BITS - 1 - (k >> 1);
        bool is_curr = (k & 1u) != 0;
        uint32_t src = is_curr ? prefix_sums[col] : prefix_sums[col + 1];
        if ((src >> b) & 1u) val = F::one();
    }
    out[k * two_c + col] = val;
}

extern "C" void *bit_decompose_prefix_sums_kernel()
{
    return (void *)bitDecomposePrefixSums<kb31_t>;
}
