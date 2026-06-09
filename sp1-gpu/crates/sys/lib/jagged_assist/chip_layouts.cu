// Device-side `ChipLayoutC` derivation. See `chip_layouts.cuh` for the
// design and contract.

#include "jagged_assist/chip_layouts.cuh"
#include "zerocheck/sequential.cuh"
#include <cstdint>

namespace {

__global__ void jaggedChipLayouts(
    const uint32_t* __restrict__ start_indices,
    const uint32_t* __restrict__ column_heights,
    const ChipColumnLayoutEntry* __restrict__ chip_entries,
    uint32_t n_chips,
    ChipLayout* __restrict__ chip_layouts
) {
    uint32_t chip_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (chip_idx >= n_chips) {
        return;
    }
    ChipColumnLayoutEntry e = chip_entries[chip_idx];

    // start_indices stores the exclusive prefix sum in *pair* units —
    // multiply by 2 to land in element units of the dense buffer.
    uint64_t prep_ptr =
        (e.prep_width > 0u) ? ((uint64_t)start_indices[e.prep_col_idx] * 2ull) : 0ull;
    uint64_t main_ptr =
        (e.main_width > 0u) ? ((uint64_t)start_indices[e.main_col_idx] * 2ull) : 0ull;

    // Chip height in element units. All columns of a chip share the same
    // height (uniform within chip — built that way and preserved by
    // `h.div_ceil(4)*2`). Prefer main if the chip has main cols, else prep,
    // else 0 (chip_idx never has both widths zero in practice but the
    // guard keeps the kernel total).
    uint32_t height_pair;
    if (e.main_width > 0u) {
        height_pair = column_heights[e.main_col_idx];
    } else if (e.prep_width > 0u) {
        height_pair = column_heights[e.prep_col_idx];
    } else {
        height_pair = 0u;
    }
    uint32_t height = height_pair * 2u;

    ChipLayout out{};
    out.main_ptr = main_ptr;
    out.preprocessed_ptr = prep_ptr;
    out.height = height;
    out._pad = 0u;
    chip_layouts[chip_idx] = out;
}

}  // namespace

extern "C" void* jagged_chip_layouts_kernel() {
    return (void*)jaggedChipLayouts;
}
