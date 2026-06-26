// Generic witness-generation interpreter kernel.
//
// Unlike the per-chip tracegen kernels (e.g. recursion/alu_base.cu), this single
// kernel interprets a recorded op-DAG (the witgen IR, `sp1_gpu_sys::WitOpC[]`) one
// thread per row, producing a gadget's trace columns. It is the device port of the
// CPU `interpret_c_columns` reference (crates/core/machine/src/air/witness_record.rs).
//
// Columns only: lookup ops (tags 6/7) emit no wire and are skipped — byte/range
// lookups come from `generate_dependencies`, not the main trace.

#include "sp1-gpu-cbindgen.hpp"

#include "fields/kb31_t.cuh"

// Max wires (inputs + value ops) per gadget. Small gadgets use < 16; the host side
// asserts the recorded program fits.
#define WITGEN_MAX_WIRES 256

template <class T>
__global__ void witgen_interp_kernel(
    T* trace,                          // output, column-major [n_cols][trace_height]
    uintptr_t trace_height,
    const sp1_gpu_sys::WitOpC* ops,    // the recorded op-DAG
    uintptr_t n_ops,
    const uint32_t* col_wires,         // column c is produced by wire col_wires[c]
    uintptr_t n_cols,
    uint32_t num_inputs,
    const uint64_t* inputs,            // row-major [n_rows][num_inputs]
    uintptr_t n_rows) {
    int row = blockIdx.x * blockDim.x + threadIdx.x;
    for (; row < n_rows; row += blockDim.x * gridDim.x) {
        uint64_t nat[WITGEN_MAX_WIRES];
        T fld[WITGEN_MAX_WIRES];
        bool is_field[WITGEN_MAX_WIRES];

        uint32_t wc = 0;
        for (uint32_t i = 0; i < num_inputs; ++i) {
            nat[wc] = inputs[row * num_inputs + i];
            is_field[wc] = false;
            ++wc;
        }

        for (uintptr_t k = 0; k < n_ops; ++k) {
            const sp1_gpu_sys::WitOpC op = ops[k];
            switch (op.tag) {
            case 0: // ConstNat
                nat[wc] = op.imm0;
                is_field[wc] = false;
                ++wc;
                break;
            case 1: // WrappingAdd (u64 wraps naturally)
                nat[wc] = nat[op.a] + nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case 8: // WrappingSub (u64 wraps naturally)
                nat[wc] = nat[op.a] - nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case 2: { // Bits: (src >> offset) & ((1<<width)-1)
                uint64_t mask = (op.imm1 >= 64) ? ~0ULL : ((1ULL << op.imm1) - 1);
                nat[wc] = (nat[op.a] >> op.imm0) & mask;
                is_field[wc] = false;
                ++wc;
                break;
            }
            case 3: // NatToField
                fld[wc] = T::from_canonical_u32((uint32_t)nat[op.a]);
                is_field[wc] = true;
                ++wc;
                break;
            case 4: // FieldAdd
                fld[wc] = fld[op.a] + fld[op.b];
                is_field[wc] = true;
                ++wc;
                break;
            case 5: // FieldInverse
                fld[wc] = fld[op.a].reciprocal();
                is_field[wc] = true;
                ++wc;
                break;
            case 6: // U16RangeCheck (lookup, no wire)
            case 7: // BitRangeCheck (lookup, no wire)
            case 9: // U8RangeCheck  (lookup, no wire)
                break;
            }
        }

        for (uintptr_t c = 0; c < n_cols; ++c) {
            uint32_t w = col_wires[c];
            trace[row + c * trace_height] =
                is_field[w] ? fld[w] : T::from_canonical_u32((uint32_t)nat[w]);
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr witgen_interp_koala_bear_kernel() {
    return (KernelPtr)::witgen_interp_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
