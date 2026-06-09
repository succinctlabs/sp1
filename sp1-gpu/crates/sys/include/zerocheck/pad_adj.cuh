// Per-chunk `padded_row_adjustment` at zero trace.
//
// The host used to compute this by running each chip's `Air::eval` against
// an all-zero trace (a single ext_t accumulator per chip — the constant
// term of the chip's constraint polynomial under the shard's challenges).
// At 5000 active chips that's a few hundred ms of CPU at shard init; more
// importantly, it's logic the device's bytecode interpreter already knows.
//
// This kernel runs the same bytecode each chunk produces, with all leaf
// loads replaced by `K::zero()` (the trace IS zero in this evaluation),
// and writes one ext_t per chunk = `Σ_assert α[chip_alpha_offset + αᵢ] · regs[root]`.
//
// Host sums the per-chunk outputs by `chip_idx` → per-chip
// `padded_row_adjustment`. Since chunks partition each chip's constraints,
// the per-chip sum equals the symbolic accumulator the CPU folder produced.
//
// Block size 64, one chunk per thread. Per-thread `regs[]` is felt_t
// (zero-trace ⇒ no extension folding), templated on the launcher's tier
// max_reg so spill stays bounded.

#pragma once

#include "zerocheck/sequential.cuh"  // ChunkStatic
#include "config.cuh"
#include <cstdint>

// Tiered entry points — same `MAX_REGS` ladder as the sequential kernel
// so the launcher can match each tier's worst-case register footprint.
extern "C" void* zerocheck_pad_adj_32_kernel();
extern "C" void* zerocheck_pad_adj_64_kernel();
extern "C" void* zerocheck_pad_adj_128_kernel();
extern "C" void* zerocheck_pad_adj_256_kernel();
extern "C" void* zerocheck_pad_adj_512_kernel();
extern "C" void* zerocheck_pad_adj_1024_kernel();
