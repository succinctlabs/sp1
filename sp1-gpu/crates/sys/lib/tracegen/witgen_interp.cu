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
            case 11: // Eq -> 0/1
                nat[wc] = (nat[op.a] == nat[op.b]) ? 1 : 0;
                is_field[wc] = false;
                ++wc;
                break;
            case 12: // Select: cond=a, then-wire=b, else-wire=imm1
                nat[wc] = nat[op.a] ? nat[op.b] : nat[op.imm1];
                is_field[wc] = false;
                ++wc;
                break;
            case 20: // Shl: a << shift
                nat[wc] = nat[op.a] << nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case 21: // Shr: a >> shift
                nat[wc] = nat[op.a] >> nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case 23: // Mul: a * b (wrapping)
                nat[wc] = nat[op.a] * nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
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
            case 19: // FieldSub
                fld[wc] = fld[op.a] - fld[op.b];
                is_field[wc] = true;
                ++wc;
                break;
            case 5: // FieldInverse
                fld[wc] = fld[op.a].reciprocal();
                is_field[wc] = true;
                ++wc;
                break;
            case 18: // FieldSelect: cond=a (nat), then-field=b, else-field=imm1
                fld[wc] = nat[op.a] ? fld[op.b] : fld[op.imm1];
                is_field[wc] = true;
                ++wc;
                break;
            case 6:  // U16RangeCheck (lookup, no wire)
            case 7:  // BitRangeCheck (lookup, no wire)
            case 9:  // U8RangeCheck  (lookup, no wire)
            case 13: // Guarded U16RangeCheck (lookup, no wire)
            case 14: // Guarded BitRangeCheck (lookup, no wire)
            case 15: // Guarded U8RangeCheck  (lookup, no wire)
            case 16: // ByteLookup           (lookup, no wire)
            case 17: // Guarded ByteLookup    (lookup, no wire)
            case 22: // BitRangeCheckVar      (lookup, no wire)
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

// --- Byte/range lookup histogram kernel (device port of `interpret_c_lookups`) ---
//
// The lookup-emitting dual of the column kernel: it interprets the SAME op-DAG one
// thread per row but, instead of writing columns, accumulates the lookup ops
// (tags 6/7/9) into two shard-level dense multiplicity tables via `atomicAdd`. The
// table index conventions match the consumer chips exactly (see range/trace.rs and
// bytes/trace.rs); the CPU reference is `interpret_c_lookups` in
// crates/core/machine/src/air/witness_record.rs.
//
// Integer-only: lookups read only Nat wires, so field-producing ops (tags 3/4/5)
// write a placeholder to keep wire ids aligned with the column interpreter.
//
// Multiplicities are u32 counts (native atomicAdd). One shard-level histogram pair,
// allocated/zeroed once by the host (heed iter-004: NO per-chunk dense arrays).
// Global atomics for now (correctness); per-block privatization is a perf follow-up.

// Byte-table multiplicity columns (== sp1_core_machine bytes::NUM_BYTE_OPS) and the
// U8Range opcode index (== sp1_core_executor::ByteOpcode::U8Range as usize).
#define WITGEN_NUM_BYTE_MULT_COLS 6
#define WITGEN_BYTE_U8RANGE_COL 3

__global__ void witgen_lookup_kernel(
    const sp1_gpu_sys::WitOpC* ops,    // the recorded op-DAG
    uintptr_t n_ops,
    uint32_t num_inputs,
    const uint64_t* inputs,            // row-major [n_rows][num_inputs]
    uintptr_t n_rows,
    uint32_t* range_hist,              // Range chip table, len 1<<17
    uint32_t* byte_hist) {             // Byte chip table, len (1<<16)*NUM_BYTE_MULT_COLS
    int row = blockIdx.x * blockDim.x + threadIdx.x;
    for (; row < n_rows; row += blockDim.x * gridDim.x) {
        uint64_t nat[WITGEN_MAX_WIRES];

        uint32_t wc = 0;
        for (uint32_t i = 0; i < num_inputs; ++i) {
            nat[wc++] = inputs[row * num_inputs + i];
        }

        for (uintptr_t k = 0; k < n_ops; ++k) {
            const sp1_gpu_sys::WitOpC op = ops[k];
            switch (op.tag) {
            case 0: // ConstNat
                nat[wc++] = op.imm0;
                break;
            case 1: // WrappingAdd
                nat[wc++] = nat[op.a] + nat[op.b];
                break;
            case 8: // WrappingSub
                nat[wc++] = nat[op.a] - nat[op.b];
                break;
            case 2: { // Bits
                uint64_t mask = (op.imm1 >= 64) ? ~0ULL : ((1ULL << op.imm1) - 1);
                nat[wc++] = (nat[op.a] >> op.imm0) & mask;
                break;
            }
            case 11: // Eq
                nat[wc++] = (nat[op.a] == nat[op.b]) ? 1 : 0;
                break;
            case 12: // Select
                nat[wc++] = nat[op.a] ? nat[op.b] : nat[op.imm1];
                break;
            case 20: // Shl
                nat[wc++] = nat[op.a] << nat[op.b];
                break;
            case 21: // Shr
                nat[wc++] = nat[op.a] >> nat[op.b];
                break;
            case 23: // Mul
                nat[wc++] = nat[op.a] * nat[op.b];
                break;
            case 3:  // NatToField
            case 4:  // FieldAdd
            case 5:  // FieldInverse
            case 18: // FieldSelect
            case 19: // FieldSub
                nat[wc++] = 0; // field wire: placeholder (never read by a lookup)
                break;
            case 6: { // U16RangeCheck -> {Range, a: v, bits: 16}
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                atomicAdd(&range_hist[v + (1u << 16)], 1u);
                break;
            }
            case 7: { // BitRangeCheck -> {Range, a: v, bits: imm0}
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                break;
            }
            case 22: { // BitRangeCheckVar -> {Range, a: v, bits: nat[op.b]}
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                uint32_t bits = (uint32_t)nat[op.b];
                atomicAdd(&range_hist[v + (1u << bits)], 1u);
                break;
            }
            case 9: { // U8RangeCheck -> {U8Range, b: nat[a], c: nat[b]}
                uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                uint32_t r = (b << 8) + c;
                atomicAdd(&byte_hist[r * WITGEN_NUM_BYTE_MULT_COLS + WITGEN_BYTE_U8RANGE_COL], 1u);
                break;
            }
            // Guarded lookups (per-row branches): emit only if the guard wire != 0.
            case 13: { // Guarded U16RangeCheck: guard wire in `b`
                if (nat[op.b]) {
                    uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                    atomicAdd(&range_hist[v + (1u << 16)], 1u);
                }
                break;
            }
            case 14: { // Guarded BitRangeCheck: guard wire in `b`, bits in imm0
                if (nat[op.b]) {
                    uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                    atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                }
                break;
            }
            case 15: { // Guarded U8RangeCheck: guard wire in `imm1`
                if (nat[op.imm1]) {
                    uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                    uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                    uint32_t r = (b << 8) + c;
                    atomicAdd(
                        &byte_hist[r * WITGEN_NUM_BYTE_MULT_COLS + WITGEN_BYTE_U8RANGE_COL], 1u);
                }
                break;
            }
            case 16: { // ByteLookup: b in a, c in b, opcode in imm1 -> index (b,c,opcode)
                uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                uint32_t opc = (uint32_t)nat[op.imm1];
                atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                break;
            }
            case 17: { // Guarded ByteLookup: guard wire in imm0
                if (nat[(uintptr_t)op.imm0]) {
                    uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                    uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                    uint32_t opc = (uint32_t)nat[op.imm1];
                    atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                }
                break;
            }
            }
        }
    }
}

// --- Fused column + lookup kernel (one op-DAG pass produces both) ---
//
// The union of `witgen_interp_kernel` and `witgen_lookup_kernel`: one thread per row
// interprets the op-DAG ONCE, writing the gadget's trace columns (value ops, as in
// the column kernel) AND accumulating its byte/range lookups into the shared shard
// histograms via atomicAdd (lookup ops, as in the lookup kernel). This removes the
// duplicate witgen pass + duplicate input upload of running the two kernels
// separately (the device deps were a separate pre-pass over the same inputs). The
// lookup-op cases are copied verbatim from `witgen_lookup_kernel`; the value-op cases
// from `witgen_interp_kernel`. Per-thread local memory is identical to the column
// kernel (nat/fld/is_field[WITGEN_MAX_WIRES]) — no new occupancy/OOM cost.
template <class T>
__global__ void witgen_fused_kernel(
    T* trace,                          // output, column-major [n_cols][trace_height]
    uintptr_t trace_height,
    const sp1_gpu_sys::WitOpC* ops,    // the recorded op-DAG
    uintptr_t n_ops,
    const uint32_t* col_wires,         // column c is produced by wire col_wires[c]
    uintptr_t n_cols,
    uint32_t num_inputs,
    const uint64_t* inputs,            // row-major [n_rows][num_inputs]
    uintptr_t n_rows,
    uint32_t* range_hist,              // Range chip table, len 1<<17
    uint32_t* byte_hist) {             // Byte chip table, len (1<<16)*NUM_BYTE_MULT_COLS
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
            // --- value ops: produce a wire (from witgen_interp_kernel) ---
            case 0: // ConstNat
                nat[wc] = op.imm0;
                is_field[wc] = false;
                ++wc;
                break;
            case 1: // WrappingAdd
                nat[wc] = nat[op.a] + nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case 8: // WrappingSub
                nat[wc] = nat[op.a] - nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case 2: { // Bits
                uint64_t mask = (op.imm1 >= 64) ? ~0ULL : ((1ULL << op.imm1) - 1);
                nat[wc] = (nat[op.a] >> op.imm0) & mask;
                is_field[wc] = false;
                ++wc;
                break;
            }
            case 11: // Eq
                nat[wc] = (nat[op.a] == nat[op.b]) ? 1 : 0;
                is_field[wc] = false;
                ++wc;
                break;
            case 12: // Select
                nat[wc] = nat[op.a] ? nat[op.b] : nat[op.imm1];
                is_field[wc] = false;
                ++wc;
                break;
            case 20: // Shl
                nat[wc] = nat[op.a] << nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case 21: // Shr
                nat[wc] = nat[op.a] >> nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case 23: // Mul
                nat[wc] = nat[op.a] * nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
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
            case 19: // FieldSub
                fld[wc] = fld[op.a] - fld[op.b];
                is_field[wc] = true;
                ++wc;
                break;
            case 5: // FieldInverse
                fld[wc] = fld[op.a].reciprocal();
                is_field[wc] = true;
                ++wc;
                break;
            case 18: // FieldSelect
                fld[wc] = nat[op.a] ? fld[op.b] : fld[op.imm1];
                is_field[wc] = true;
                ++wc;
                break;
            // --- lookup ops: no wire, accumulate histogram (from witgen_lookup_kernel) ---
            case 6: { // U16RangeCheck
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                atomicAdd(&range_hist[v + (1u << 16)], 1u);
                break;
            }
            case 7: { // BitRangeCheck
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                break;
            }
            case 22: { // BitRangeCheckVar
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                uint32_t bits = (uint32_t)nat[op.b];
                atomicAdd(&range_hist[v + (1u << bits)], 1u);
                break;
            }
            case 9: { // U8RangeCheck
                uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                uint32_t r = (b << 8) + c;
                atomicAdd(&byte_hist[r * WITGEN_NUM_BYTE_MULT_COLS + WITGEN_BYTE_U8RANGE_COL], 1u);
                break;
            }
            case 13: { // Guarded U16RangeCheck
                if (nat[op.b]) {
                    uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                    atomicAdd(&range_hist[v + (1u << 16)], 1u);
                }
                break;
            }
            case 14: { // Guarded BitRangeCheck
                if (nat[op.b]) {
                    uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                    atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                }
                break;
            }
            case 15: { // Guarded U8RangeCheck
                if (nat[op.imm1]) {
                    uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                    uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                    uint32_t r = (b << 8) + c;
                    atomicAdd(
                        &byte_hist[r * WITGEN_NUM_BYTE_MULT_COLS + WITGEN_BYTE_U8RANGE_COL], 1u);
                }
                break;
            }
            case 16: { // ByteLookup
                uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                uint32_t opc = (uint32_t)nat[op.imm1];
                atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                break;
            }
            case 17: { // Guarded ByteLookup
                if (nat[(uintptr_t)op.imm0]) {
                    uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                    uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                    uint32_t opc = (uint32_t)nat[op.imm1];
                    atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                }
                break;
            }
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
extern KernelPtr witgen_lookup_koala_bear_kernel() {
    return (KernelPtr)::witgen_lookup_kernel;
}
extern KernelPtr witgen_fused_koala_bear_kernel() {
    return (KernelPtr)::witgen_fused_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
