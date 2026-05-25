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
#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

namespace {

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

    // Eval point index. Diff-doubling: eval points are {0, 2, 4}; the leaf
    // interpolation `z + ep * (o - z)` is rewritten as `z + d2 (+ d2)` with
    // `d2 = diff + diff` so we never multiply by a felt.
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
        ext_t acc = ext_t::zero();

        for (uint32_t i = 0; i < stc.n_instrs; i++) {
            DagInstr instr = stc.instrs[i];
            switch (instr.opcode) {
            case BC_LOAD_LEAF: {
                LeafRef leaf = stc.leaves[instr.a];
                // source: 2 = preprocessed, 4 = main (local row only).
                size_t base = (leaf.source == 4) ? lay.main_ptr : lay.preprocessed_ptr;
                // 64-bit column stride math; u32 × u32 wraps near the
                // 2^32 / height column count. See review #6.
                size_t col_off = (size_t)leaf.col * (size_t)lay.height;
                K z = K::load(trace_data, base + col_off + (row_idx << 1));
                if (e == 0) {
                    regs[instr.out] = z;
                } else {
                    K o = K::load(trace_data, base + col_off + (row_idx << 1 | 1));
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

        for (uint32_t i = 0; i < stc.n_asserts; i++) {
            uint16_t reg = stc.assert_regs[i];
            // Bytecode stores chip-relative alpha indices; shift into the
            // cluster's powers_of_alpha table here.
            uint32_t alpha_idx = stc.chip_alpha_offset + stc.assert_alphas[i];
            ext_t alpha = ext_t::load(powers_of_alpha, alpha_idx);
            acc += alpha * regs[reg];
        }

        // Inline GKR column sweep for the carrier chunk of NARROW chips
        // (the launcher zeroes these widths for wide chips, which get GKR
        // via the dedicated `zerocheck_gkr_sweep` kernel). Inline keeps
        // the column reads in L1 alongside the constraint leaf reads,
        // which matters for narrow widths.
        //
        // Geq correction is always out-of-band (`zerocheck_geq_corrections`).
        if (stc.gkr_main_width != 0 || stc.gkr_prep_width != 0) {
            // 64-bit column stride math; u32 × u32 wraps near
            // `2^32 / height` columns. See review #6.
            const size_t height_64 = (size_t)lay.height;
            for (uint32_t i = 0; i < stc.gkr_main_width; i++) {
                size_t col_off = (size_t)i * height_64;
                K z = K::load(trace_data, lay.main_ptr + col_off + (row_idx << 1));
                K v;
                if (e == 0) {
                    v = z;
                } else {
                    K o = K::load(trace_data,
                                  lay.main_ptr + col_off + (row_idx << 1 | 1));
                    K diff = o - z;
                    K d2 = diff + diff;
                    v = (e == 1) ? (z + d2) : (z + d2 + d2);
                }
                acc += ext_t::load(gkr_powers, i) * v;
            }
            for (uint32_t i = 0; i < stc.gkr_prep_width; i++) {
                size_t col_off = (size_t)i * height_64;
                K z = K::load(trace_data, lay.preprocessed_ptr + col_off + (row_idx << 1));
                K v;
                if (e == 0) {
                    v = z;
                } else {
                    K o = K::load(trace_data,
                                  lay.preprocessed_ptr + col_off + (row_idx << 1 | 1));
                    K diff = o - z;
                    K d2 = diff + diff;
                    v = (e == 1) ? (z + d2) : (z + d2 + d2);
                }
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
