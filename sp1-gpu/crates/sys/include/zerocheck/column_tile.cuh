// ColumnTile lowering for v2 zerocheck.
//
// Handles `Σ_k α^k · (Σ_i coeff_{k,i} · leaf_{k,i})` chunks. One lane per
// `(term, row, eval)` tuple. No shared-mem cache — lane variation IS the
// program; each lane reads its own `(zero, one)` directly from global.

#pragma once

#include "config.cuh"
#include "zerocheck/sequential.cuh"   // re-uses LeafRef
#include <cstdint>

// Must match `ColumnTermEntry` in column_tile_bytecode.rs.
struct ColumnTermEntry {
    uint32_t leaf_idx;
    uint32_t coeff_kind;   // 0 = const, 1 = public
    uint32_t coeff_idx;
    uint32_t alpha_idx;
};

constexpr uint32_t COEFF_KIND_CONST   = 0;
constexpr uint32_t COEFF_KIND_PUBLIC  = 1;
constexpr uint32_t COEFF_KIND_RUNTIME = 2;

extern "C" void* zerocheck_column_tile_kb_kernel();
extern "C" void* zerocheck_column_tile_ext_kernel();
