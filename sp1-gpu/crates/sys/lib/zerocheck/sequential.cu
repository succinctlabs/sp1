// Sequential lowering — DAG bytecode interpreter over a flat machine-wide
// instruction stream.
//
// Each CTA grid-strides over rows. Each thread = one row: it binary-searches
// `row_starts` to find its chunk, runs that chunk's bytecode, weights the
// result by `eq · λ_chip`, and accumulates into a per-thread sum that is
// block-reduced into one partial per CTA per eval point.
//
// Templated on `K` ∈ {felt_t, ext_t}:
//   - Round 0 of sumcheck uses K = felt_t (base-field trace).
//   - Rounds 1+ use K = ext_t (the trace has been folded with extension-field
//     challenges).
// Constants and public values are always base-field; runtime coeffs and the
// per-row weighting/accumulator are always ext_t.

#include "zerocheck/sequential.cuh"
#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

namespace {

// ============================================================================
// Fused dispatch kernel: one launch handles every Sequential chunk in the
// round. Each thread binary-searches `row_starts` to find its chunk, then
// runs that chunk's bytecode.
//
// Output: one ext_t per (block, eval point), stored at `blockIdx.x * 3 + e`
// (block-reduced across all rows the block touched, regardless of which
// chunks). The chip-specific weighting (eq * λ_chip) is applied INSIDE the
// per-row body, so the cross-chunk sum is unambiguous — chip totals are NOT
// separately tracked.
//
// The three eval points (the degree-2 univariate per round) live on the grid's
// z-dimension: each block owns one eval point (blockIdx.z) and reduces it
// independently. This keeps the per-thread register file minimal and lets the
// GPU run all three eval points concurrently. Measured faster than having one
// block compute all three at every round size from millions of rows down to a
// handful, since the per-block reduces then run in parallel rather than
// serially.
// ============================================================================

__device__ __forceinline__ uint32_t
upper_bound_u32_local(const uint32_t* arr, uint32_t n, uint32_t target) {
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = (lo + hi) >> 1;
        if (arr[mid] <= target) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

template <typename K, int MAX_REGS>
__global__ void zerocheck_fused_sequential(
    const ChunkMeta* __restrict__ chunk_meta,
    const uint32_t* __restrict__ row_starts,  // n_chunks + 1 entries
    uint32_t n_chunks,
    uint32_t total_rows,
    const K* __restrict__ trace_data,
    const felt_t* __restrict__ public_values,
    const ext_t* __restrict__ powers_of_alpha,
    const ext_t* __restrict__ partial_lagrange,
    const ext_t* __restrict__ powers_of_lambda,
    const ext_t* __restrict__ gkr_powers,
    uint32_t rest_point_dim,
    ext_t* __restrict__ partials
) {
    // This block's eval point index. Each thread handles ONE eval point, so
    // the register file is single-dimensional. Eval points are {0, 2, 4};
    // the leaf interpolation `z + ep * (o - z)` is rewritten as add doublings
    // (z + d2 / z + d2 + d2 with d2 = diff + diff) to avoid a felt-by-K mul.
    const int e = blockIdx.z;

    K regs[MAX_REGS];
    ext_t thread_acc = ext_t::zero();

    const uint32_t stride = blockDim.x * gridDim.x;
    const uint32_t row_limit = 1u << rest_point_dim;

    for (uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
         idx < total_rows;
         idx += stride)
    {
        // Find chunk index for this idx.
        uint32_t chunk_idx = upper_bound_u32_local(row_starts, n_chunks + 1, idx) - 1;
        uint32_t row_idx = idx - row_starts[chunk_idx];
        ChunkMeta cm = chunk_meta[chunk_idx];
        const felt_t* consts = reinterpret_cast<const felt_t*>(cm.consts);

        ext_t acc = ext_t::zero();

        for (uint32_t i = 0; i < cm.n_instrs; i++) {
            DagInstr instr = cm.instrs[i];
            switch (instr.opcode) {
            case BC_LOAD_LEAF: {
                LeafRef leaf = cm.leaves[instr.a];
                // source: 2 = preprocessed, 4 = main (local row only).
                size_t base = (leaf.source == 4) ? cm.main_ptr : cm.preprocessed_ptr;
                K z = K::load(trace_data, base + leaf.col * cm.height + (row_idx << 1));
                if (e == 0) {
                    regs[instr.out] = z;
                } else {
                    K o = K::load(trace_data,
                                  base + leaf.col * cm.height + (row_idx << 1 | 1));
                    // Diff-doubling: see kernel banner. e is uniform across
                    // the block, so the ternary is a uniform branch.
                    K diff = o - z;
                    K d2 = diff + diff;          // 2 * diff
                    regs[instr.out] = (e == 1) ? (z + d2)            // z + 2*diff
                                               : (z + d2 + d2);      // z + 4*diff
                }
                break;
            }
            case BC_LOAD_CONST: {
                regs[instr.out] = K(consts[instr.a]);
                break;
            }
            case BC_LOAD_PUBLIC: {
                uint32_t pv_idx = cm.publics[instr.a];
                regs[instr.out] = K(felt_t::load(public_values, pv_idx));
                break;
            }
            case BC_ADD_F: {
                regs[instr.out] = regs[instr.a] + regs[instr.b];
                break;
            }
            case BC_SUB_F: {
                regs[instr.out] = regs[instr.a] - regs[instr.b];
                break;
            }
            case BC_MUL_F: {
                regs[instr.out] = regs[instr.a] * regs[instr.b];
                break;
            }
            case BC_NEG_F: {
                regs[instr.out] = K::zero() - regs[instr.a];
                break;
            }
            default:
                break;
            }
        }

        for (uint32_t i = 0; i < cm.n_asserts; i++) {
            uint16_t reg = cm.assert_regs[i];
            // Bytecode stores chip-relative alpha indices; shift into the
            // cluster's powers_of_alpha table here.
            uint32_t alpha_idx = cm.chip_alpha_offset + cm.assert_alphas[i];
            ext_t alpha = ext_t::load(powers_of_alpha, alpha_idx);
            acc += alpha * regs[reg];
        }

        if (cm.gkr_main_width != 0 || cm.gkr_prep_width != 0) {
            // Same diff-doubling trick as BC_LOAD_LEAF for the GKR carrier
            // columns: `z + ep*(o-z)` becomes `z + d2` or `z + d2 + d2`.
            for (uint32_t i = 0; i < cm.gkr_main_width; i++) {
                K z = K::load(trace_data, cm.main_ptr + i * cm.height + (row_idx << 1));
                K v;
                if (e == 0) {
                    v = z;
                } else {
                    K o = K::load(trace_data, cm.main_ptr + i * cm.height + (row_idx << 1 | 1));
                    K diff = o - z;
                    K d2 = diff + diff;
                    v = (e == 1) ? (z + d2) : (z + d2 + d2);
                }
                ext_t bp = ext_t::load(gkr_powers, i);
                acc += bp * v;
            }
            for (uint32_t i = 0; i < cm.gkr_prep_width; i++) {
                K z = K::load(trace_data,
                              cm.preprocessed_ptr + i * cm.height + (row_idx << 1));
                K v;
                if (e == 0) {
                    v = z;
                } else {
                    K o = K::load(trace_data,
                                  cm.preprocessed_ptr + i * cm.height + (row_idx << 1 | 1));
                    K diff = o - z;
                    K d2 = diff + diff;
                    v = (e == 1) ? (z + d2) : (z + d2 + d2);
                }
                ext_t bp = ext_t::load(gkr_powers, cm.gkr_main_width + i);
                acc += bp * v;
            }

            // Geq correction — subtract `geq(row, eval_pt) * padded_row_adjustment`
            // from acc. Carrier chunk (gkr_main_width > 0) is the natural place
            // since each chip's geq fires exactly once. Moving this from a host
            // loop into the kernel was a big win: the host loop iterated
            // row_count rows × 9 ext ops per row per chip per round.
            uint32_t z_idx = row_idx << 1;
            uint32_t o_idx = (row_idx << 1) | 1;
            ext_t geq_z, geq_o;
            if (z_idx < cm.geq_threshold) {
                geq_z = ext_t::zero();
            } else if (z_idx == cm.geq_threshold) {
                geq_z = ext_t::one() + cm.geq_eq_coefficient;
            } else {
                geq_z = ext_t::one();
            }
            if (o_idx < cm.geq_threshold) {
                geq_o = ext_t::zero();
            } else if (o_idx == cm.geq_threshold) {
                geq_o = ext_t::one() + cm.geq_eq_coefficient;
            } else {
                geq_o = ext_t::one();
            }
            ext_t geq_v;
            if (e == 0) {
                geq_v = geq_z;
            } else {
                ext_t gdiff = geq_o - geq_z;
                ext_t gd2 = gdiff + gdiff;
                geq_v = (e == 1) ? (geq_z + gd2) : (geq_z + gd2 + gd2);
            }
            acc -= geq_v * cm.padded_row_adjustment;
        }

        if (row_idx < row_limit) {
            ext_t eq = ext_t::load(partial_lagrange, row_idx);
            ext_t lambda = ext_t::load(powers_of_lambda, cm.chip_idx);
            thread_acc += acc * (eq * lambda);
        }
    }

    extern __shared__ unsigned char smem[];
    ext_t* shared = reinterpret_cast<ext_t*>(smem);

    auto block = cg::this_thread_block();
    auto tile_warp = cg::tiled_partition<32>(block);

    ext_t block_sum = partialBlockReduce(block, tile_warp, thread_acc, shared);
    if (threadIdx.x == 0) {
        // Output layout: eval point e of block.x lives at (block.x * 3 + e).
        ext_t::store(partials, blockIdx.x * 3 + (uint32_t)e, block_sum);
    }
}

} // namespace

// Fused dispatch entry points, tiered by MAX_REGS so the per-thread local
// memory footprint matches the largest chunk in the tier. The launcher
// partitions seq_meta into tiers and launches one fused kernel per non-empty
// tier (typically 1-2 launches per round on real workloads).
extern "C" void* zerocheck_fused_sequential_kb_32_kernel() {
    return (void*)zerocheck_fused_sequential<felt_t, 32>;
}
extern "C" void* zerocheck_fused_sequential_kb_64_kernel() {
    return (void*)zerocheck_fused_sequential<felt_t, 64>;
}
extern "C" void* zerocheck_fused_sequential_kb_128_kernel() {
    return (void*)zerocheck_fused_sequential<felt_t, 128>;
}
extern "C" void* zerocheck_fused_sequential_kb_256_kernel() {
    return (void*)zerocheck_fused_sequential<felt_t, 256>;
}
extern "C" void* zerocheck_fused_sequential_kb_512_kernel() {
    return (void*)zerocheck_fused_sequential<felt_t, 512>;
}
extern "C" void* zerocheck_fused_sequential_kb_1024_kernel() {
    return (void*)zerocheck_fused_sequential<felt_t, 1024>;
}
extern "C" void* zerocheck_fused_sequential_ext_32_kernel() {
    return (void*)zerocheck_fused_sequential<ext_t, 32>;
}
extern "C" void* zerocheck_fused_sequential_ext_64_kernel() {
    return (void*)zerocheck_fused_sequential<ext_t, 64>;
}
extern "C" void* zerocheck_fused_sequential_ext_128_kernel() {
    return (void*)zerocheck_fused_sequential<ext_t, 128>;
}
extern "C" void* zerocheck_fused_sequential_ext_256_kernel() {
    return (void*)zerocheck_fused_sequential<ext_t, 256>;
}
extern "C" void* zerocheck_fused_sequential_ext_512_kernel() {
    return (void*)zerocheck_fused_sequential<ext_t, 512>;
}
extern "C" void* zerocheck_fused_sequential_ext_1024_kernel() {
    return (void*)zerocheck_fused_sequential<ext_t, 1024>;
}

// Back-compat entry points (deprecated: use the tiered variants).
extern "C" void* zerocheck_fused_sequential_kb_kernel() {
    return (void*)zerocheck_fused_sequential<felt_t, 128>;
}
extern "C" void* zerocheck_fused_sequential_ext_kernel() {
    return (void*)zerocheck_fused_sequential<ext_t, 128>;
}
