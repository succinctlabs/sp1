// Sequential lowering for the DAG-native zerocheck.
//
// Interprets a chunk's bytecode per row, computing one ext_t partial per
// (block, eval point). Mirrors the host-side `ChunkBytecode` layout from
// `sp1-gpu-air/src/ir/bytecode.rs`.

#pragma once

#include "config.cuh"
#include <cstdint>

// Must match `DagInstr` in sp1-gpu-air/src/ir/bytecode.rs.
struct DagInstr {
    uint8_t opcode;
    uint8_t _pad;
    uint16_t out;
    uint16_t a;
    uint16_t b;
};

// Source tag for `LeafRef.source`. Must match
// `LEAF_SOURCE_{PREPROCESSED,MAIN}_LOCAL` in
// `sp1-gpu-air/src/ir/bytecode.rs`. The (`PreprocessedNext`,
// `MainNext`) variants from the jagged-mle column tags would be 3 and 5
// but are never emitted here — constraint lowering only references local
// rows.
constexpr uint8_t LEAF_SOURCE_PREPROCESSED_LOCAL = 2;
constexpr uint8_t LEAF_SOURCE_MAIN_LOCAL         = 4;

// Must match `LeafRef` in sp1-gpu-air/src/ir/bytecode.rs.
struct LeafRef {
    uint8_t source;   // LEAF_SOURCE_PREPROCESSED_LOCAL / LEAF_SOURCE_MAIN_LOCAL
    uint8_t _pad;
    uint32_t col;
};

// Opcodes — must match `BcOp` in sp1-gpu-air/src/ir/bytecode.rs.
// Asserts aren't an opcode: they live in a separate per-chunk
// `(reg, alpha_idx)` array (`stc.asserts`) so the interpreter can iterate
// them after the bytecode body, summed against `powers_of_alpha`.
enum BcOp : uint8_t {
    BC_LOAD_LEAF   = 0,
    BC_LOAD_CONST  = 1,
    BC_LOAD_PUBLIC = 2,
    BC_ADD_F       = 3,
    BC_SUB_F       = 4,
    BC_MUL_F       = 5,
    BC_NEG_F       = 6,
};

// Shard-static per-chunk descriptor. Must match `ChunkStaticC` in
// zerocheck/src/prover.rs (layout-compat). Uploaded once per shard, reused
// across all rounds — none of its fields depend on the per-round trace fold.
struct ChunkStatic {
    const DagInstr* instrs;            // 8
    const LeafRef* leaves;             // 8
    const void* consts;                // 8 — cast to felt_t* in kernel
    const uint32_t* publics;           // 8
    const uint16_t* assert_regs;       // 8
    const uint32_t* assert_alphas;     // 8
    uint32_t n_instrs;                 // 4
    uint32_t n_asserts;                // 4
    uint32_t chip_idx;                 // 4
    /// Carrier-chunk inline-GKR widths. Set non-zero ONLY for narrow chips
    /// (total width ≤ WIDE_GKR_THRESHOLD) where keeping the column sweep
    /// inline preserves L1 cache locality with constraint leaf reads. Wide
    /// chips get GKR via the dedicated `zerocheck_gkr_sweep` kernel and
    /// have these zeroed at shard init.
    uint32_t gkr_main_width;           // 4
    uint32_t gkr_prep_width;           // 4
    uint32_t chip_alpha_offset;        // 4 — added to chip-relative alpha idx
};

// Per-round per-chip trace pointers + height. Must match `ChipLayoutC` in
// zerocheck/src/prover.rs (layout-compat). Indexed by chip_idx — the kernel
// reads `chip_layouts[chunk_static.chip_idx]` after reading the chunk.
struct ChipLayout {
    uint64_t main_ptr;                 // 8
    uint64_t preprocessed_ptr;         // 8
    uint32_t height;                   // 4
    uint32_t _pad;                     // 4
};

// Per-block dispatch entry. One per launched block; the kernel reads
// `dispatch[blockIdx.x]` once at block init and handles `n_rows` rows
// starting at `row_offset` of chunk `chunk_id`. Must match `BlockDispatchC`
// in zerocheck/src/prover.rs.
struct BlockDispatch {
    uint32_t chunk_id;                 // 4
    uint32_t row_offset;               // 4
    uint32_t n_rows;                   // 4
};

// Fused dispatch kernel. One launch handles every Sequential chunk tile
// produced by the host-side dispatch builder. Each block reads its
// `BlockDispatch` once at block init — no per-row binary search.
//
// Tiered variants by MAX_REGS — the launcher partitions chunks into tiers
// and launches one kernel per non-empty tier so each kernel's per-thread
// register array is sized to its tier's worst case (not the entire
// workload's worst case).
extern "C" void* zerocheck_fused_sequential_kb_32_kernel();
extern "C" void* zerocheck_fused_sequential_kb_64_kernel();
extern "C" void* zerocheck_fused_sequential_kb_128_kernel();
extern "C" void* zerocheck_fused_sequential_kb_256_kernel();
extern "C" void* zerocheck_fused_sequential_kb_512_kernel();
extern "C" void* zerocheck_fused_sequential_kb_1024_kernel();
extern "C" void* zerocheck_fused_sequential_ext_32_kernel();
extern "C" void* zerocheck_fused_sequential_ext_64_kernel();
extern "C" void* zerocheck_fused_sequential_ext_128_kernel();
extern "C" void* zerocheck_fused_sequential_ext_256_kernel();
extern "C" void* zerocheck_fused_sequential_ext_512_kernel();
extern "C" void* zerocheck_fused_sequential_ext_1024_kernel();

// Bivariate (fused first-two-rounds) variants: eval nodes on blockIdx.z
// (12 nodes), quadruple row consumption, output stride 12. Round 0 only —
// base-field trace, so no ext instantiations. See zerocheck/bivariate.cuh.
extern "C" void* zerocheck_fused_sequential_bivariate_kb_32_kernel();
extern "C" void* zerocheck_fused_sequential_bivariate_kb_64_kernel();
extern "C" void* zerocheck_fused_sequential_bivariate_kb_128_kernel();
extern "C" void* zerocheck_fused_sequential_bivariate_kb_256_kernel();
extern "C" void* zerocheck_fused_sequential_bivariate_kb_512_kernel();
extern "C" void* zerocheck_fused_sequential_bivariate_kb_1024_kernel();
