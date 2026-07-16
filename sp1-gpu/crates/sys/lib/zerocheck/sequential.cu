// Sequential lowering — DAG bytecode interpreter, dispatched block-per-tile.
//
// The launcher partitions each Sequential chunk into row tiles and builds a
// `BlockDispatch[]` table — one entry per launched block. Each block:
//
//   1. Reads `dispatch[blockIdx.x]` once at block init.
//   2. Loads the chunk's static descriptor (`ChunkStatic`) and the chip's
//      per-round trace layout (`ChipLayout`) — uniform across all threads in
//      the block, so the compiler can hoist these into a single load.
//   3. Each thread strides through its share of the tile's `n_rows` rows,
//      running the chunk's bytecode and weighting by `eq · λ_chip`.
//   4. The block reduces the per-thread accumulator into one ext_t per eval
//      point and writes the output at `blockIdx.x * 3 + e`.
//
// Replaces the previous per-row `upper_bound` binary search on `row_starts`
// (O(log n_chunks) per row, plus per-row `ChunkMeta` loads). The new path
// has O(1) per-block dispatch with all metadata loaded exactly once per
// block — uniform reads, no cache thrashing as chunk counts grow.
//
// Templated on `K` ∈ {felt_t, ext_t}:
//   - Round 0 of sumcheck uses K = felt_t (base-field trace).
//   - Rounds 1+ use K = ext_t (the trace has been folded with extension-field
//     challenges).
// Constants and public values are always base-field; runtime coeffs and the
// per-row weighting/accumulator are always ext_t.
//
// The three eval points (the degree-2 univariate per round) live on the
// grid's z-dimension: each block owns one eval point (blockIdx.z) and
// reduces it independently. This keeps the per-thread register file minimal
// and lets the GPU run all three eval points concurrently.

#include "zerocheck/sequential.cuh"
#include "zerocheck/bivariate.cuh"
#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

namespace {

// Run one chunk's DAG bytecode for a single row position, then batch the
// assertion registers by their alpha powers, returning the chunk's
// constraint accumulator. Shared by the univariate and bivariate kernels,
// which differ only in how a leaf's trace value is interpolated —
// `load_leaf(LeafRef) -> K` supplies it.
template <typename K, int MAX_REGS, typename LoadLeaf>
__device__ __forceinline__ ext_t run_chunk_bytecode(
    const ChunkStatic& stc,
    const felt_t* consts,
    const felt_t* public_values,
    const ext_t* powers_of_alpha,
    K (&regs)[MAX_REGS],
    LoadLeaf load_leaf)
{
    for (uint32_t i = 0; i < stc.n_instrs; i++) {
        DagInstr instr = stc.instrs[i];
        switch (instr.opcode) {
        case BC_LOAD_LEAF: {
            regs[instr.out] = load_leaf(stc.leaves[instr.a]);
            break;
        }
        case BC_LOAD_CONST: {
            regs[instr.out] = K(consts[instr.a]);
            break;
        }
        case BC_LOAD_PUBLIC: {
            uint32_t pv_idx = stc.publics[instr.a];
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
            // Unknown opcode = Rust↔CUDA bytecode drift; fail loudly
            // rather than leaving `regs[instr.out]` stale and silently
            // producing the wrong constraint value downstream.
            __trap();
        }
    }

    ext_t acc = ext_t::zero();
    for (uint32_t i = 0; i < stc.n_asserts; i++) {
        uint16_t reg = stc.assert_regs[i];
        // Bytecode stores chip-relative alpha indices; shift into the
        // cluster's powers_of_alpha table here.
        uint32_t alpha_idx = stc.chip_alpha_offset + stc.assert_alphas[i];
        ext_t alpha = ext_t::load(powers_of_alpha, alpha_idx);
        acc += alpha * regs[reg];
    }
    return acc;
}

template <typename K, int MAX_REGS>
__global__ void zerocheck_fused_sequential(
    const BlockDispatch* __restrict__ dispatch,
    const ChunkStatic* __restrict__ chunk_static,
    const ChipLayout* __restrict__ chip_layouts,
    const K* __restrict__ trace_data,
    const felt_t* __restrict__ public_values,
    const ext_t* __restrict__ powers_of_alpha,
    const ext_t* __restrict__ partial_lagrange,
    const ext_t* __restrict__ powers_of_lambda,
    const ext_t* __restrict__ gkr_powers,
    uint32_t rest_point_dim,
    ext_t* __restrict__ partials
) {
    // Per-block uniform setup. The compiler hoists these loads — every
    // thread in the block sees the same dispatch/static/layout values.
    BlockDispatch disp = dispatch[blockIdx.x];
    ChunkStatic stc = chunk_static[disp.chunk_id];
    ChipLayout lay = chip_layouts[stc.chip_idx];
    const felt_t* consts = reinterpret_cast<const felt_t*>(stc.consts);

    // Eval point index into the univariate nodes {0, 2, 4}; see
    // `interp_load_pair` for the diff-doubling interpolation.
    const int e = blockIdx.z;

    K regs[MAX_REGS];
    ext_t thread_acc = ext_t::zero();

    const uint32_t row_limit = 1u << rest_point_dim;
    const uint32_t row_end = disp.row_offset + disp.n_rows;

    // Stride through this tile's rows. Each thread handles `n_rows /
    // blockDim.x` rows; for the launcher's chosen tile sizes that's a few
    // rows per thread, which amortises the per-block reduce cost.
    for (uint32_t row_idx = disp.row_offset + threadIdx.x;
         row_idx < row_end;
         row_idx += blockDim.x)
    {
        ext_t acc = run_chunk_bytecode(
            stc, consts, public_values, powers_of_alpha, regs, [&](LeafRef leaf) {
                size_t base = (leaf.source == LEAF_SOURCE_MAIN_LOCAL)
                                  ? lay.main_ptr
                                  : lay.preprocessed_ptr;
                return interp_load_pair(trace_data, base, leaf.col, lay.height, row_idx, e);
            });

        // Inline GKR column sweep for the carrier chunk of NARROW chips
        // (the launcher zeroes these widths for wide chips, which get GKR
        // via the dedicated `zerocheck_gkr_sweep` kernel). Inline keeps
        // the column reads in L1 alongside the constraint leaf reads,
        // which matters for narrow widths.
        //
        // Geq correction is always out-of-band (`zerocheck_geq_corrections`).
        if (stc.gkr_main_width != 0 || stc.gkr_prep_width != 0) {
            for (uint32_t i = 0; i < stc.gkr_main_width; i++) {
                K v = interp_load_pair(trace_data, lay.main_ptr, i, lay.height, row_idx, e);
                acc += ext_t::load(gkr_powers, i) * v;
            }
            for (uint32_t i = 0; i < stc.gkr_prep_width; i++) {
                K v = interp_load_pair(
                    trace_data, lay.preprocessed_ptr, i, lay.height, row_idx, e);
                acc += ext_t::load(gkr_powers, stc.gkr_main_width + i) * v;
            }
        }

        if (row_idx < row_limit) {
            ext_t eq = ext_t::load(partial_lagrange, row_idx);
            ext_t lambda = ext_t::load(powers_of_lambda, stc.chip_idx);
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

// ============================================================================
// Bivariate variant — the fused first-two-rounds evaluation.
//
// Rows are consumed in QUADRUPLES (element index `4·quad + 2·X + Y`), and each
// block computes ALL 12 non-boolean grid nodes of `{0, 1, 2, 4}^2`: per row,
// the node loop re-runs the chunk's bytecode once per node, so the trace is
// pulled from DRAM once and the 11 repeat passes hit L1/L2 (per-thread
// temporal locality on the same quadruple). This trades compute (the
// interpreter runs 12× per row either way) for a single pass over memory —
// the round-message cost is pass-count-bound, not compute-bound.
// Only run for round 0, so only the felt_t instantiations are exported.
//
// Differences from the univariate kernel above:
//   - No blockIdx.z: the launcher's grid is (n_blocks, 1, 1).
//   - No inline GKR sweep: the boolean corner nodes are handled by the
//     dedicated `zerocheck_gkr_corner_sweep` kernel for every chip.
//   - Loads are guarded against the column height: heights are even but not
//     necessarily multiples of four, so the last quadruple of a chip may have
//     only two physical rows; the missing rows are zero (matching the virtual
//     zero padding of the trace MLE). Reading past `lay.height` would land in
//     the next column's data.
//   - Output stride is 12: each block writes nodes e = 0..12 at
//     (block.x * 12 + e).
// ============================================================================

template <typename K, int MAX_REGS>
__global__ void zerocheck_fused_sequential_bivariate(
    const BlockDispatch* __restrict__ dispatch,
    const ChunkStatic* __restrict__ chunk_static,
    const ChipLayout* __restrict__ chip_layouts,
    const K* __restrict__ trace_data,
    const felt_t* __restrict__ public_values,
    const ext_t* __restrict__ powers_of_alpha,
    const ext_t* __restrict__ partial_lagrange,
    const ext_t* __restrict__ powers_of_lambda,
    uint32_t rest_point_dim,
    ext_t* __restrict__ partials
) {
    BlockDispatch disp = dispatch[blockIdx.x];
    ChunkStatic stc = chunk_static[disp.chunk_id];
    ChipLayout lay = chip_layouts[stc.chip_idx];
    const felt_t* consts = reinterpret_cast<const felt_t*>(stc.consts);
    const ext_t lambda = ext_t::load(powers_of_lambda, stc.chip_idx);

    K regs[MAX_REGS];
    // One accumulator per grid node. Indexed by the (non-unrolled) node loop,
    // so it lives in L1-cached local memory rather than bloating the register
    // file on top of `regs[]`.
    ext_t thread_acc[BIVARIATE_NUM_NODES];
    for (int e = 0; e < BIVARIATE_NUM_NODES; e++) {
        thread_acc[e] = ext_t::zero();
    }

    const uint32_t quad_limit = 1u << rest_point_dim;
    const uint32_t quad_end = disp.row_offset + disp.n_rows;

    for (uint32_t quad_idx = disp.row_offset + threadIdx.x;
         quad_idx < quad_end;
         quad_idx += blockDim.x)
    {
        // Rows at or above the eq range contribute nothing (their true
        // contribution is zero); skip the bytecode entirely.
        if (quad_idx >= quad_limit) {
            continue;
        }
        const ext_t w = ext_t::load(partial_lagrange, quad_idx) * lambda;
        // Heights are even, so only rows 2 and 3 of the chip's last
        // quadruple can be missing; uniform across the block except at the
        // chip's boundary quad.
        const bool full_quad = ((quad_idx << 2) | 3u) < lay.height;

        for (int e = 0; e < BIVARIATE_NUM_NODES; e++) {
            const BivariateNode node = bivariate_node(e);
            ext_t acc = run_chunk_bytecode(
                stc, consts, public_values, powers_of_alpha, regs, [&](LeafRef leaf) {
                    size_t base = (leaf.source == LEAF_SOURCE_MAIN_LOCAL)
                                      ? lay.main_ptr
                                      : lay.preprocessed_ptr;
                    return interp_load_quad(
                        trace_data, base, leaf.col, lay.height, quad_idx, full_quad, node);
                });

            thread_acc[e] += acc * w;
        }
    }

    extern __shared__ unsigned char smem[];
    ext_t* shared = reinterpret_cast<ext_t*>(smem);

    auto block = cg::this_thread_block();
    auto tile_warp = cg::tiled_partition<32>(block);

    for (int e = 0; e < BIVARIATE_NUM_NODES; e++) {
        ext_t block_sum = partialBlockReduce(block, tile_warp, thread_acc[e], shared);
        if (threadIdx.x == 0) {
            ext_t::store(partials, blockIdx.x * BIVARIATE_NUM_NODES + (uint32_t)e, block_sum);
        }
        block.sync();
    }
}

} // namespace

// Fused dispatch entry points, tiered by MAX_REGS so the per-thread local
// memory footprint matches the largest chunk in the tier. The launcher
// partitions chunks into tiers and launches one fused kernel per non-empty
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

// Bivariate (fused first-two-rounds) entry points. Round 0 only, so only the
// base-field instantiations exist.
extern "C" void* zerocheck_fused_sequential_bivariate_kb_32_kernel() {
    return (void*)zerocheck_fused_sequential_bivariate<felt_t, 32>;
}
extern "C" void* zerocheck_fused_sequential_bivariate_kb_64_kernel() {
    return (void*)zerocheck_fused_sequential_bivariate<felt_t, 64>;
}
extern "C" void* zerocheck_fused_sequential_bivariate_kb_128_kernel() {
    return (void*)zerocheck_fused_sequential_bivariate<felt_t, 128>;
}
extern "C" void* zerocheck_fused_sequential_bivariate_kb_256_kernel() {
    return (void*)zerocheck_fused_sequential_bivariate<felt_t, 256>;
}
extern "C" void* zerocheck_fused_sequential_bivariate_kb_512_kernel() {
    return (void*)zerocheck_fused_sequential_bivariate<felt_t, 512>;
}
extern "C" void* zerocheck_fused_sequential_bivariate_kb_1024_kernel() {
    return (void*)zerocheck_fused_sequential_bivariate<felt_t, 1024>;
}
