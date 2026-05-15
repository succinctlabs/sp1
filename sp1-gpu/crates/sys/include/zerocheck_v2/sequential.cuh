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
    uint8_t source;   // 2=PrepLocal, 3=PrepNext, 4=MainLocal, 5=MainNext
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

// Entry points used by Rust via `KernelPtr`. Returns the device function
// pointer; the actual kernels are `zerocheck_v2_sequential<K, MAX_REGS>`.
//   - kb_kernel:  K = felt_t  (base-field trace, round 0 of sumcheck)
//   - ext_kernel: K = ext_t   (extension-field trace, rounds 1+)
extern "C" void* zerocheck_v2_sequential_kb_kernel();
extern "C" void* zerocheck_v2_sequential_ext_kernel();

// Tiered variants by per-chunk MAX_REGS. The chunk's `max_reg` selects the
// smallest tier whose MAX_REGS >= max_reg. Tight sizing matters for perf:
// `K regs[MAX_REGS][3]` is a per-thread stack array that spills to local
// memory, so an over-sized MAX_REGS pays a real load/store cost per row.
extern "C" void* zerocheck_v2_sequential_kb_32_kernel();
extern "C" void* zerocheck_v2_sequential_kb_64_kernel();
extern "C" void* zerocheck_v2_sequential_kb_128_kernel();
extern "C" void* zerocheck_v2_sequential_kb_256_kernel();
extern "C" void* zerocheck_v2_sequential_ext_32_kernel();
extern "C" void* zerocheck_v2_sequential_ext_64_kernel();
extern "C" void* zerocheck_v2_sequential_ext_128_kernel();
extern "C" void* zerocheck_v2_sequential_ext_256_kernel();

// Per-chunk metadata for the fused dispatch kernel. One ChunkMeta entry per
// Sequential chunk that the round wants to evaluate. Must match
// `ChunkMetaC` in v2.rs (layout-compat).
//
// All per-chunk buffer pointers are device pointers into separate
// (per-chunk) buffers — we don't concatenate at this stage, because each
// chunk's bytecode/leaves are uploaded once and reused across rounds.
struct ChunkMeta {
    const DagInstr* instrs;            // 8
    const LeafRef* leaves;             // 8
    const void* consts;                // 8 — cast to felt_t* in kernel
    const uint32_t* publics;           // 8
    const uint16_t* assert_regs;       // 8
    const uint32_t* assert_alphas;     // 8
    uint64_t preprocessed_ptr;         // 8
    uint64_t main_ptr;                 // 8
    uint32_t n_instrs;                 // 4
    uint32_t n_asserts;                // 4
    uint32_t chip_idx;                 // 4
    uint32_t gkr_main_width;           // 4
    uint32_t gkr_prep_width;           // 4
    uint32_t height;                   // 4
    uint32_t row_count;                // 4
    uint32_t chip_alpha_offset;        // 4 — added to chip-relative alpha idx
    uint32_t geq_threshold;            // 4 — applied iff gkr_main_width != 0
    ext_t geq_eq_coefficient;          // 16
    ext_t padded_row_adjustment;       // 16
};

// Fused dispatch kernel. One launch handles every Sequential chunk across
// every chip. Each thread binary-searches `row_starts` to find which chunk
// its `idx` belongs to, then runs that chunk's bytecode.
//
// Tiered variants by MAX_REGS — the launcher partitions chunks into tiers
// and launches one kernel per non-empty tier so each kernel's per-thread
// register array is sized to its tier's worst case (not the entire
// workload's worst case).
extern "C" void* zerocheck_v2_fused_sequential_kb_kernel();
extern "C" void* zerocheck_v2_fused_sequential_ext_kernel();
extern "C" void* zerocheck_v2_fused_sequential_kb_32_kernel();
extern "C" void* zerocheck_v2_fused_sequential_kb_64_kernel();
extern "C" void* zerocheck_v2_fused_sequential_kb_128_kernel();
extern "C" void* zerocheck_v2_fused_sequential_kb_256_kernel();
extern "C" void* zerocheck_v2_fused_sequential_kb_512_kernel();
extern "C" void* zerocheck_v2_fused_sequential_kb_1024_kernel();
extern "C" void* zerocheck_v2_fused_sequential_ext_32_kernel();
extern "C" void* zerocheck_v2_fused_sequential_ext_64_kernel();
extern "C" void* zerocheck_v2_fused_sequential_ext_128_kernel();
extern "C" void* zerocheck_v2_fused_sequential_ext_256_kernel();
extern "C" void* zerocheck_v2_fused_sequential_ext_512_kernel();
extern "C" void* zerocheck_v2_fused_sequential_ext_1024_kernel();
