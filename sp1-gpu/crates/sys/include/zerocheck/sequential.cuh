// Sequential lowering for v2 zerocheck.
//
// Interprets a chunk's bytecode per row, computing 3 eval-point partial sums
// per CTA. Matches the host-side `ChunkBytecode` layout from
// sp1-gpu-air/src/v2/bytecode.rs.
//
// Phase 2 scope: base-field DAG nodes only. Output is unweighted (no
// partial_lagrange / lambda multiplication). The host weighting + final
// reduction happens in a follow-up phase.

#pragma once

#include "config.cuh"
#include <cstdint>

// Must match `DagInstr` in v2/bytecode.rs.
struct DagInstr {
    uint8_t opcode;
    uint8_t _pad;
    uint16_t out;
    uint16_t a;
    uint16_t b;
};

// Must match `LeafRef` in v2/bytecode.rs.
struct LeafRef {
    uint8_t source;   // 2=PrepLocal, 4=MainLocal (local row only)
    uint8_t _pad;
    uint32_t col;
};

// Opcodes — must match `BcOp` in v2/bytecode.rs.
enum BcOp : uint8_t {
    BC_LOAD_LEAF   = 0,
    BC_LOAD_CONST  = 1,
    BC_LOAD_PUBLIC = 2,
    BC_ADD_F       = 3,
    BC_SUB_F       = 4,
    BC_MUL_F       = 5,
    BC_NEG_F       = 6,
    BC_ASSERT_F    = 7,
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
extern "C" void* zerocheck_fused_sequential_kb_kernel();
extern "C" void* zerocheck_fused_sequential_ext_kernel();
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
