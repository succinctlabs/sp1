// v2 Sequential lowering — DAG bytecode interpreter with eval-point caching.
//
// Each CTA processes a tile of rows. Each thread = one row. Per-thread state
// is a register file of `MAX_REGS` × 3 K values (one slot per eval point),
// so leaf (zero, one) loads happen ONCE per thread per leaf and feed all
// three eval points without re-loading.
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

__device__ __forceinline__ felt_t eval_point(int i) {
    return felt_t::from_canonical_u32(2u * i);
}

template <typename K, int MAX_REGS>
__global__ void zerocheck_sequential(
    const DagInstr* __restrict__ instrs,
    uint32_t n_instrs,
    const LeafRef* __restrict__ leaves,
    const felt_t* __restrict__ consts,
    const uint32_t* __restrict__ publics,
    const uint16_t* __restrict__ assert_regs,
    const uint32_t* __restrict__ assert_alphas,
    uint32_t n_asserts,
    const K* __restrict__ trace_data,
    size_t preprocessed_ptr,
    size_t main_ptr,
    uint32_t height,
    const felt_t* __restrict__ public_values,
    const ext_t* __restrict__ powers_of_alpha,
    const ext_t* __restrict__ partial_lagrange,
    const ext_t* __restrict__ powers_of_lambda,
    uint32_t chip_idx,
    uint32_t rest_point_dim,
    uint32_t row_start,
    uint32_t row_count,
    // GKR fusion: if both widths are non-zero, the kernel appends a per-row
    // column sweep `Σ_i gkr_powers[i] · col_i(row)` after the bytecode +
    // asserts pass, sharing column loads with the constraint reads.
    // gkr_powers[0..main_w-1] weight main cols, gkr_powers[main_w..main_w+prep_w-1] weight prep cols.
    const ext_t* __restrict__ gkr_powers,
    uint32_t gkr_main_width,
    uint32_t gkr_prep_width,
    ext_t* __restrict__ partials
) {
    K regs[MAX_REGS][3];
    ext_t thread_acc[3] = { ext_t::zero(), ext_t::zero(), ext_t::zero() };

    const uint32_t stride = blockDim.x * gridDim.x;
    const ext_t lambda = ext_t::load(powers_of_lambda, chip_idx);
    const uint32_t row_limit = 1u << rest_point_dim;

    // Grid-stride loop: amortize launch + reduce overhead across many rows.
    for (uint32_t lane = blockIdx.x * blockDim.x + threadIdx.x;
         lane < row_count;
         lane += stride)
    {
        const uint32_t row_idx = row_start + lane;
        ext_t acc[3] = { ext_t::zero(), ext_t::zero(), ext_t::zero() };

        for (uint32_t i = 0; i < n_instrs; i++) {
            DagInstr instr = instrs[i];
            switch (instr.opcode) {
            case BC_LOAD_LEAF: {
                LeafRef leaf = leaves[instr.a];
                size_t base = (leaf.source == 4 || leaf.source == 5)
                                ? main_ptr
                                : preprocessed_ptr;
                K z = K::load(trace_data, base + leaf.col * height + (row_idx << 1));
                K o = K::load(trace_data, base + leaf.col * height + (row_idx << 1 | 1));
                K diff = o - z;
                regs[instr.out][0] = z;
                regs[instr.out][1] = z + eval_point(1) * diff;
                regs[instr.out][2] = z + eval_point(2) * diff;
                break;
            }
            case BC_LOAD_CONST: {
                K c = K(consts[instr.a]);
                regs[instr.out][0] = c;
                regs[instr.out][1] = c;
                regs[instr.out][2] = c;
                break;
            }
            case BC_LOAD_PUBLIC: {
                uint32_t pv_idx = publics[instr.a];
                K v = K(felt_t::load(public_values, pv_idx));
                regs[instr.out][0] = v;
                regs[instr.out][1] = v;
                regs[instr.out][2] = v;
                break;
            }
            case BC_ADD_F: {
                regs[instr.out][0] = regs[instr.a][0] + regs[instr.b][0];
                regs[instr.out][1] = regs[instr.a][1] + regs[instr.b][1];
                regs[instr.out][2] = regs[instr.a][2] + regs[instr.b][2];
                break;
            }
            case BC_SUB_F: {
                regs[instr.out][0] = regs[instr.a][0] - regs[instr.b][0];
                regs[instr.out][1] = regs[instr.a][1] - regs[instr.b][1];
                regs[instr.out][2] = regs[instr.a][2] - regs[instr.b][2];
                break;
            }
            case BC_MUL_F: {
                regs[instr.out][0] = regs[instr.a][0] * regs[instr.b][0];
                regs[instr.out][1] = regs[instr.a][1] * regs[instr.b][1];
                regs[instr.out][2] = regs[instr.a][2] * regs[instr.b][2];
                break;
            }
            case BC_NEG_F: {
                regs[instr.out][0] = K::zero() - regs[instr.a][0];
                regs[instr.out][1] = K::zero() - regs[instr.a][1];
                regs[instr.out][2] = K::zero() - regs[instr.a][2];
                break;
            }
            default:
                break;
            }
        }

        for (uint32_t i = 0; i < n_asserts; i++) {
            uint16_t reg = assert_regs[i];
            uint32_t alpha_idx = assert_alphas[i];
            ext_t alpha = ext_t::load(powers_of_alpha, alpha_idx);
            acc[0] += alpha * regs[reg][0];
            acc[1] += alpha * regs[reg][1];
            acc[2] += alpha * regs[reg][2];
        }

        // GKR sweep — appended in-thread to share row's column reads with
        // the constraint pass. With main_w + prep_w columns and one mult-add
        // per col per eval point, this is what the synthesized GKR ColumnTile
        // chunk would otherwise do in a separate launch.
        if (gkr_main_width != 0 || gkr_prep_width != 0) {
            for (uint32_t i = 0; i < gkr_main_width; i++) {
                K z = K::load(trace_data, main_ptr + i * height + (row_idx << 1));
                K o = K::load(trace_data, main_ptr + i * height + (row_idx << 1 | 1));
                K diff = o - z;
                ext_t bp = ext_t::load(gkr_powers, i);
                acc[0] += bp * z;
                acc[1] += bp * (z + eval_point(1) * diff);
                acc[2] += bp * (z + eval_point(2) * diff);
            }
            for (uint32_t i = 0; i < gkr_prep_width; i++) {
                K z = K::load(trace_data, preprocessed_ptr + i * height + (row_idx << 1));
                K o = K::load(trace_data, preprocessed_ptr + i * height + (row_idx << 1 | 1));
                K diff = o - z;
                ext_t bp = ext_t::load(gkr_powers, gkr_main_width + i);
                acc[0] += bp * z;
                acc[1] += bp * (z + eval_point(1) * diff);
                acc[2] += bp * (z + eval_point(2) * diff);
            }
        }

        if (row_idx < row_limit) {
            ext_t eq = ext_t::load(partial_lagrange, row_idx);
            ext_t w = eq * lambda;
            thread_acc[0] += acc[0] * w;
            thread_acc[1] += acc[1] * w;
            thread_acc[2] += acc[2] * w;
        }
    }

    extern __shared__ unsigned char smem[];
    ext_t* shared = reinterpret_cast<ext_t*>(smem);

    auto block = cg::this_thread_block();
    auto tile_warp = cg::tiled_partition<32>(block);

    for (int e = 0; e < 3; e++) {
        ext_t block_sum = partialBlockReduce(block, tile_warp, thread_acc[e], shared);
        if (threadIdx.x == 0) {
            ext_t::store(partials, blockIdx.x * 3 + e, block_sum);
        }
        __syncthreads();
    }
}

// ============================================================================
// Fused dispatch kernel: one launch handles every Sequential chunk in the
// round. Each thread binary-searches `row_starts` to find its chunk, then
// runs that chunk's bytecode.
//
// Output: one ext_t[3] per block (block-reduced across all rows the block
// touched, regardless of which chunks). The chip-specific weighting
// (eq * λ_chip) is applied INSIDE the per-row body, so the cross-chunk sum
// is unambiguous — chip totals are NOT separately tracked.
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
    // The eval-point axis lives on grid_z (matches v1's design): each thread
    // handles ONE eval point and the per-thread register file is
    // single-dimensional. Stashing all 3 eval points in regs[MAX_REGS][3]
    // tripled register pressure and forced heavy local-memory spilling
    // (profiling showed 5.9M local loads + 3.3M stores per launch). With
    // grid_z=3 the same total work runs across 3x more blocks, each block
    // has 1/3 the per-thread state, and the GPU schedules them concurrently.
    K regs[MAX_REGS];
    ext_t thread_acc = ext_t::zero();

    const uint32_t stride = blockDim.x * gridDim.x;
    const uint32_t row_limit = 1u << rest_point_dim;
    const int e = blockIdx.z;
    const felt_t ep_v = (e == 0) ? felt_t::zero()
                       : felt_t::from_canonical_u32(2u * (uint32_t)e);

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
                size_t base = (leaf.source == 4 || leaf.source == 5)
                                ? cm.main_ptr
                                : cm.preprocessed_ptr;
                K z = K::load(trace_data, base + leaf.col * cm.height + (row_idx << 1));
                if (e == 0) {
                    regs[instr.out] = z;
                } else {
                    K o = K::load(trace_data,
                                  base + leaf.col * cm.height + (row_idx << 1 | 1));
                    regs[instr.out] = z + ep_v * (o - z);
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
            for (uint32_t i = 0; i < cm.gkr_main_width; i++) {
                K z = K::load(trace_data, cm.main_ptr + i * cm.height + (row_idx << 1));
                K v;
                if (e == 0) {
                    v = z;
                } else {
                    K o = K::load(trace_data, cm.main_ptr + i * cm.height + (row_idx << 1 | 1));
                    v = z + ep_v * (o - z);
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
                    v = z + ep_v * (o - z);
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
            ext_t geq_v = (e == 0) ? geq_z : (geq_z + ep_v * (geq_o - geq_z));
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
        // Output layout: blockIdx.z slot lives at (block.x * 3 + e). Matches
        // the existing host aggregation that sums 3 ext per block.
        ext_t::store(partials, blockIdx.x * 3 + (uint32_t)e, block_sum);
    }
}

} // namespace

// Tiered register-file sizes. Each chunk picks the smallest tier whose
// MAX_REGS >= chunk.max_reg. Larger MAX_REGS means more local-memory
// spilling (compile-time-sized stack array) so picking tightly matters a lot.

extern "C" void* zerocheck_sequential_kb_32_kernel() {
    return (void*)zerocheck_sequential<felt_t, 32>;
}
extern "C" void* zerocheck_sequential_kb_64_kernel() {
    return (void*)zerocheck_sequential<felt_t, 64>;
}
extern "C" void* zerocheck_sequential_kb_128_kernel() {
    return (void*)zerocheck_sequential<felt_t, 128>;
}
extern "C" void* zerocheck_sequential_kb_256_kernel() {
    return (void*)zerocheck_sequential<felt_t, 256>;
}

extern "C" void* zerocheck_sequential_ext_32_kernel() {
    return (void*)zerocheck_sequential<ext_t, 32>;
}
extern "C" void* zerocheck_sequential_ext_64_kernel() {
    return (void*)zerocheck_sequential<ext_t, 64>;
}
extern "C" void* zerocheck_sequential_ext_128_kernel() {
    return (void*)zerocheck_sequential<ext_t, 128>;
}
extern "C" void* zerocheck_sequential_ext_256_kernel() {
    return (void*)zerocheck_sequential<ext_t, 256>;
}

// Back-compat default (used by code that doesn't tier yet).
extern "C" void* zerocheck_sequential_kb_kernel() {
    return (void*)zerocheck_sequential<felt_t, 256>;
}
extern "C" void* zerocheck_sequential_ext_kernel() {
    return (void*)zerocheck_sequential<ext_t, 256>;
}

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
