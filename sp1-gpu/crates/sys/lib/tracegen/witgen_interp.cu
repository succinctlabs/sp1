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
            case 24: // Xor
                nat[wc] = nat[op.a] ^ nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case 25: // And
                nat[wc] = nat[op.a] & nat[op.b];
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
            case 24: // Xor
                nat[wc++] = nat[op.a] ^ nat[op.b];
                break;
            case 25: // And
                nat[wc++] = nat[op.a] & nat[op.b];
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
            case 24: // Xor
                nat[wc] = nat[op.a] ^ nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case 25: // And
                nat[wc] = nat[op.a] & nat[op.b];
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

// --- Byte/Range lookup-table trace from the shared histogram ---
//
// The Byte and Range table chips' traces ARE the dense multiplicity histograms (each
// cell = the lookup count), so once the device-dependency chips have accumulated the
// shared histogram we can build these traces directly on-device — no readback, no host
// `byte_lookups` reconstruction, no CPU `generate_trace`. This kernel converts the
// row-major u32 histogram (`hist[row * n_cols + col]`, matching range/trace.rs and
// bytes/trace.rs), so the conversion is a pure element-wise u32->field cast; the caller
// transposes the result to the column-major MLE via the existing `DeviceTensor::transpose`
// path (exactly as host traces). Host-chip lookups (chips not on the device) are
// scattered in separately first (see `hist_trace_scatter_kernel`).
template <class T>
__global__ void hist_to_trace_kernel(T* trace, const uint32_t* hist, uintptr_t total) {
    for (uintptr_t i = blockIdx.x * blockDim.x + threadIdx.x; i < total;
         i += (uintptr_t)blockDim.x * gridDim.x) {
        trace[i] = T::from_canonical_u32(hist[i]);
    }
}

// Scatter-add the host chips' lookups into the row-major u32 histogram BEFORE the
// conversion: each (row_major_index, mult) entry adds `mult` to one histogram cell.
// `idxs[i]` is the pre-computed row-major offset `row * n_cols + col`; `mults[i]` the
// multiplicity. Used for the (few) chips whose dependencies are NOT generated on the
// device, so the host work is O(host lookups), not O(histogram).
__global__ void hist_trace_scatter_kernel(
    uint32_t* hist,
    const uint64_t* idxs,
    const uint32_t* mults,
    uintptr_t n) {
    // Host-map keys are unique, so each `idxs[i]` is distinct → no atomics needed.
    for (uintptr_t i = blockIdx.x * blockDim.x + threadIdx.x; i < n;
         i += (uintptr_t)blockDim.x * gridDim.x) {
        hist[idxs[i]] += mults[i];
    }
}

// --- Slot-indexed (register-allocated) variants for WIDE gadgets ---
//
// Same interpreter as `witgen_interp_kernel` / `witgen_lookup_kernel`, but the
// per-thread wire array is indexed by REUSED slots (`op.out`, and operand fields
// a/b/imm1/imm0 pre-remapped host-side by `WitProgram::to_c_slots`) instead of the
// SSA `wc++`. This bounds the array by max-live slots (Mul: 531 wires -> 100 slots)
// so wide gadgets fit `WITGEN_MAX_WIRES` without raising it. Device port of the CPU
// reference `interpret_c_slots_columns` (crates/core/machine/.../witness_record.rs).
// Inputs are written to their slots via `input_slots`; columns read `col_slots[c]`.
template <class T>
__global__ void witgen_interp_slots_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::WitOpCSlot* ops,
    uintptr_t n_ops,
    const uint32_t* col_slots,         // column c is produced by slot col_slots[c]
    uintptr_t n_cols,
    uint32_t num_inputs,
    const uint32_t* input_slots,       // input i lives in slot input_slots[i]
    const uint64_t* inputs,            // row-major [n_rows][num_inputs]
    uintptr_t n_rows) {
    int row = blockIdx.x * blockDim.x + threadIdx.x;
    for (; row < n_rows; row += blockDim.x * gridDim.x) {
        uint64_t nat[WITGEN_MAX_WIRES];
        T fld[WITGEN_MAX_WIRES];
        bool is_field[WITGEN_MAX_WIRES];

        for (uint32_t i = 0; i < num_inputs; ++i) {
            uint32_t s = input_slots[i];
            nat[s] = inputs[row * num_inputs + i];
            is_field[s] = false;
        }

        for (uintptr_t k = 0; k < n_ops; ++k) {
            const sp1_gpu_sys::WitOpCSlot op = ops[k];
            switch (op.tag) {
            case 0: // ConstNat
                nat[op.out] = op.imm0;
                is_field[op.out] = false;
                break;
            case 1: // WrappingAdd
                nat[op.out] = nat[op.a] + nat[op.b];
                is_field[op.out] = false;
                break;
            case 8: // WrappingSub
                nat[op.out] = nat[op.a] - nat[op.b];
                is_field[op.out] = false;
                break;
            case 2: { // Bits
                uint64_t mask = (op.imm1 >= 64) ? ~0ULL : ((1ULL << op.imm1) - 1);
                nat[op.out] = (nat[op.a] >> op.imm0) & mask;
                is_field[op.out] = false;
                break;
            }
            case 11: // Eq
                nat[op.out] = (nat[op.a] == nat[op.b]) ? 1 : 0;
                is_field[op.out] = false;
                break;
            case 12: // Select
                nat[op.out] = nat[op.a] ? nat[op.b] : nat[op.imm1];
                is_field[op.out] = false;
                break;
            case 20: // Shl
                nat[op.out] = nat[op.a] << nat[op.b];
                is_field[op.out] = false;
                break;
            case 21: // Shr
                nat[op.out] = nat[op.a] >> nat[op.b];
                is_field[op.out] = false;
                break;
            case 23: // Mul
                nat[op.out] = nat[op.a] * nat[op.b];
                is_field[op.out] = false;
                break;
            case 24: // Xor
                nat[op.out] = nat[op.a] ^ nat[op.b];
                is_field[op.out] = false;
                break;
            case 25: // And
                nat[op.out] = nat[op.a] & nat[op.b];
                is_field[op.out] = false;
                break;
            case 3: // NatToField
                fld[op.out] = T::from_canonical_u32((uint32_t)nat[op.a]);
                is_field[op.out] = true;
                break;
            case 4: // FieldAdd
                fld[op.out] = fld[op.a] + fld[op.b];
                is_field[op.out] = true;
                break;
            case 19: // FieldSub
                fld[op.out] = fld[op.a] - fld[op.b];
                is_field[op.out] = true;
                break;
            case 5: // FieldInverse
                fld[op.out] = fld[op.a].reciprocal();
                is_field[op.out] = true;
                break;
            case 18: // FieldSelect
                fld[op.out] = nat[op.a] ? fld[op.b] : fld[op.imm1];
                is_field[op.out] = true;
                break;
            case 6:  // lookups: no wire
            case 7:
            case 9:
            case 13:
            case 14:
            case 15:
            case 16:
            case 17:
            case 22:
                break;
            }
        }

        for (uintptr_t c = 0; c < n_cols; ++c) {
            uint32_t s = col_slots[c];
            trace[row + c * trace_height] =
                is_field[s] ? fld[s] : T::from_canonical_u32((uint32_t)nat[s]);
        }
    }
}

// Slot-indexed lookup histogram kernel (register-allocated dual of
// `witgen_lookup_kernel`). Value ops write `nat[op.out]`; lookup ops read operand
// slots exactly as the SSA version (operands pre-remapped by `to_c_slots`).
__global__ void witgen_lookup_slots_kernel(
    const sp1_gpu_sys::WitOpCSlot* ops,
    uintptr_t n_ops,
    uint32_t num_inputs,
    const uint32_t* input_slots,
    const uint64_t* inputs,
    uintptr_t n_rows,
    uint32_t* range_hist,
    uint32_t* byte_hist) {
    int row = blockIdx.x * blockDim.x + threadIdx.x;
    for (; row < n_rows; row += blockDim.x * gridDim.x) {
        uint64_t nat[WITGEN_MAX_WIRES];

        for (uint32_t i = 0; i < num_inputs; ++i) {
            nat[input_slots[i]] = inputs[row * num_inputs + i];
        }

        for (uintptr_t k = 0; k < n_ops; ++k) {
            const sp1_gpu_sys::WitOpCSlot op = ops[k];
            switch (op.tag) {
            case 0: nat[op.out] = op.imm0; break;
            case 1: nat[op.out] = nat[op.a] + nat[op.b]; break;
            case 8: nat[op.out] = nat[op.a] - nat[op.b]; break;
            case 2: {
                uint64_t mask = (op.imm1 >= 64) ? ~0ULL : ((1ULL << op.imm1) - 1);
                nat[op.out] = (nat[op.a] >> op.imm0) & mask;
                break;
            }
            case 11: nat[op.out] = (nat[op.a] == nat[op.b]) ? 1 : 0; break;
            case 12: nat[op.out] = nat[op.a] ? nat[op.b] : nat[op.imm1]; break;
            case 20: nat[op.out] = nat[op.a] << nat[op.b]; break;
            case 21: nat[op.out] = nat[op.a] >> nat[op.b]; break;
            case 23: nat[op.out] = nat[op.a] * nat[op.b]; break;
            case 24: nat[op.out] = nat[op.a] ^ nat[op.b]; break;
            case 25: nat[op.out] = nat[op.a] & nat[op.b]; break;
            case 3:  // field ops: placeholder (never read by a lookup)
            case 4:
            case 5:
            case 18:
            case 19:
                nat[op.out] = 0;
                break;
            case 6: {
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                atomicAdd(&range_hist[v + (1u << 16)], 1u);
                break;
            }
            case 7: {
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                break;
            }
            case 22: {
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                uint32_t bits = (uint32_t)nat[op.b];
                atomicAdd(&range_hist[v + (1u << bits)], 1u);
                break;
            }
            case 9: {
                uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                uint32_t r = (b << 8) + c;
                atomicAdd(&byte_hist[r * WITGEN_NUM_BYTE_MULT_COLS + WITGEN_BYTE_U8RANGE_COL], 1u);
                break;
            }
            case 13: {
                if (nat[op.b]) {
                    uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                    atomicAdd(&range_hist[v + (1u << 16)], 1u);
                }
                break;
            }
            case 14: {
                if (nat[op.b]) {
                    uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                    atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                }
                break;
            }
            case 15: {
                if (nat[op.imm1]) {
                    uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                    uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                    uint32_t r = (b << 8) + c;
                    atomicAdd(
                        &byte_hist[r * WITGEN_NUM_BYTE_MULT_COLS + WITGEN_BYTE_U8RANGE_COL], 1u);
                }
                break;
            }
            case 16: {
                uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                uint32_t opc = (uint32_t)nat[op.imm1];
                atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                break;
            }
            case 17: {
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

// Slot-indexed FUSED kernel (columns + lookups in one op-DAG pass) for WIDE gadgets —
// the register-allocated union of witgen_interp_slots_kernel + witgen_lookup_slots_kernel,
// mirroring witgen_fused_kernel. Used by device-dependency chips (e.g. Mul) whose prove
// path is the fused `generate_trace_device_with_lookups`.
template <class T>
__global__ void witgen_fused_slots_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::WitOpCSlot* ops,
    uintptr_t n_ops,
    const uint32_t* col_slots,
    uintptr_t n_cols,
    uint32_t num_inputs,
    const uint32_t* input_slots,
    const uint64_t* inputs,
    uintptr_t n_rows,
    uint32_t* range_hist,
    uint32_t* byte_hist) {
    int row = blockIdx.x * blockDim.x + threadIdx.x;
    for (; row < n_rows; row += blockDim.x * gridDim.x) {
        uint64_t nat[WITGEN_MAX_WIRES];
        T fld[WITGEN_MAX_WIRES];
        bool is_field[WITGEN_MAX_WIRES];

        for (uint32_t i = 0; i < num_inputs; ++i) {
            uint32_t s = input_slots[i];
            nat[s] = inputs[row * num_inputs + i];
            is_field[s] = false;
        }

        for (uintptr_t k = 0; k < n_ops; ++k) {
            const sp1_gpu_sys::WitOpCSlot op = ops[k];
            switch (op.tag) {
            // --- value ops (from witgen_interp_slots_kernel) ---
            case 0:
                nat[op.out] = op.imm0;
                is_field[op.out] = false;
                break;
            case 1:
                nat[op.out] = nat[op.a] + nat[op.b];
                is_field[op.out] = false;
                break;
            case 8:
                nat[op.out] = nat[op.a] - nat[op.b];
                is_field[op.out] = false;
                break;
            case 2: {
                uint64_t mask = (op.imm1 >= 64) ? ~0ULL : ((1ULL << op.imm1) - 1);
                nat[op.out] = (nat[op.a] >> op.imm0) & mask;
                is_field[op.out] = false;
                break;
            }
            case 11:
                nat[op.out] = (nat[op.a] == nat[op.b]) ? 1 : 0;
                is_field[op.out] = false;
                break;
            case 12:
                nat[op.out] = nat[op.a] ? nat[op.b] : nat[op.imm1];
                is_field[op.out] = false;
                break;
            case 20:
                nat[op.out] = nat[op.a] << nat[op.b];
                is_field[op.out] = false;
                break;
            case 21:
                nat[op.out] = nat[op.a] >> nat[op.b];
                is_field[op.out] = false;
                break;
            case 23:
                nat[op.out] = nat[op.a] * nat[op.b];
                is_field[op.out] = false;
                break;
            case 24:
                nat[op.out] = nat[op.a] ^ nat[op.b];
                is_field[op.out] = false;
                break;
            case 25:
                nat[op.out] = nat[op.a] & nat[op.b];
                is_field[op.out] = false;
                break;
            case 3:
                fld[op.out] = T::from_canonical_u32((uint32_t)nat[op.a]);
                is_field[op.out] = true;
                break;
            case 4:
                fld[op.out] = fld[op.a] + fld[op.b];
                is_field[op.out] = true;
                break;
            case 19:
                fld[op.out] = fld[op.a] - fld[op.b];
                is_field[op.out] = true;
                break;
            case 5:
                fld[op.out] = fld[op.a].reciprocal();
                is_field[op.out] = true;
                break;
            case 18:
                fld[op.out] = nat[op.a] ? fld[op.b] : fld[op.imm1];
                is_field[op.out] = true;
                break;
            // --- lookup ops (from witgen_lookup_slots_kernel) ---
            case 6: {
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                atomicAdd(&range_hist[v + (1u << 16)], 1u);
                break;
            }
            case 7: {
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                break;
            }
            case 22: {
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                uint32_t bits = (uint32_t)nat[op.b];
                atomicAdd(&range_hist[v + (1u << bits)], 1u);
                break;
            }
            case 9: {
                uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                uint32_t r = (b << 8) + c;
                atomicAdd(&byte_hist[r * WITGEN_NUM_BYTE_MULT_COLS + WITGEN_BYTE_U8RANGE_COL], 1u);
                break;
            }
            case 13: {
                if (nat[op.b]) {
                    uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                    atomicAdd(&range_hist[v + (1u << 16)], 1u);
                }
                break;
            }
            case 14: {
                if (nat[op.b]) {
                    uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                    atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                }
                break;
            }
            case 15: {
                if (nat[op.imm1]) {
                    uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                    uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                    uint32_t r = (b << 8) + c;
                    atomicAdd(
                        &byte_hist[r * WITGEN_NUM_BYTE_MULT_COLS + WITGEN_BYTE_U8RANGE_COL], 1u);
                }
                break;
            }
            case 16: {
                uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                uint32_t opc = (uint32_t)nat[op.imm1];
                atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                break;
            }
            case 17: {
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
            uint32_t s = col_slots[c];
            trace[row + c * trace_height] =
                is_field[s] ? fld[s] : T::from_canonical_u32((uint32_t)nat[s]);
        }
    }
}

// STREAMING (store-through) fused kernel with SHARED-MEMORY wires, for chips whose
// streaming footprint fits WIRE_CAP (iter-073 census: 15/20 chips <= 24 transient
// slots once columns are written at production instead of pinned for a readout).
//
// vs witgen_fused_slots_kernel: (1) wires live in __shared__ ([slot][thread] layout,
// bank-conflict-free) instead of DRAM-backed local arrays — the local-memory traffic
// WAS the witgen cost (iter-072); (2) ops carry `col`: a single-column wire is stored
// to the trace at production (no readout loop, no col_slots); (3) `is_field[]` is
// gone — the store type is static per tag; (4) input-columns stored at load;
// (5) multi-column wires via the (slot,col) epilogue (census: always empty, kept for
// correctness). Lookup arms are identical to witgen_fused_slots_kernel.
#define WITGEN_SMEM_CAP 24
#define WITGEN_SMEM_BLOCK 64

template <class T>
__global__ void __launch_bounds__(WITGEN_SMEM_BLOCK) witgen_fused_streaming_smem_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::WitOpCSlot* ops,
    uintptr_t n_ops,
    uint32_t num_inputs,
    const uint32_t* input_slots,       // input i lives in slot input_slots[i]
    const uint32_t* input_col_idx,     // input-columns: (input index, col) pairs
    const uint32_t* input_col_col,
    uint32_t n_input_cols,
    const uint32_t* epi_slot,          // epilogue: (slot, col) pairs
    const uint32_t* epi_col,
    uint32_t n_epi,
    const uint64_t* inputs,            // row-major [n_rows][num_inputs]
    uintptr_t n_rows,
    uint32_t* range_hist,
    uint32_t* byte_hist) {
    __shared__ uint64_t nat_s[WITGEN_SMEM_CAP * WITGEN_SMEM_BLOCK];
    __shared__ T fld_s[WITGEN_SMEM_CAP * WITGEN_SMEM_BLOCK];
    const uint32_t tid = threadIdx.x;
    // [slot][thread]: consecutive threads -> consecutive banks.
#define NATS(s) nat_s[(s) * WITGEN_SMEM_BLOCK + tid]
#define FLDS(s) fld_s[(s) * WITGEN_SMEM_BLOCK + tid]

    int row = blockIdx.x * blockDim.x + threadIdx.x;
    for (; row < n_rows; row += blockDim.x * gridDim.x) {
        for (uint32_t i = 0; i < num_inputs; ++i) {
            NATS(input_slots[i]) = inputs[row * num_inputs + i];
        }
        for (uint32_t i = 0; i < n_input_cols; ++i) {
            trace[row + (uintptr_t)input_col_col[i] * trace_height] =
                T::from_canonical_u32((uint32_t)inputs[row * num_inputs + input_col_idx[i]]);
        }

        for (uintptr_t k = 0; k < n_ops; ++k) {
            const sp1_gpu_sys::WitOpCSlot op = ops[k];
            bool is_fld = false;
            switch (op.tag) {
            case 0: NATS(op.out) = op.imm0; break;
            case 1: NATS(op.out) = NATS(op.a) + NATS(op.b); break;
            case 8: NATS(op.out) = NATS(op.a) - NATS(op.b); break;
            case 2: {
                uint64_t mask = (op.imm1 >= 64) ? ~0ULL : ((1ULL << op.imm1) - 1);
                NATS(op.out) = (NATS(op.a) >> op.imm0) & mask;
                break;
            }
            case 11: NATS(op.out) = (NATS(op.a) == NATS(op.b)) ? 1 : 0; break;
            case 12: NATS(op.out) = NATS(op.a) ? NATS(op.b) : NATS(op.imm1); break;
            case 20: NATS(op.out) = NATS(op.a) << NATS(op.b); break;
            case 21: NATS(op.out) = NATS(op.a) >> NATS(op.b); break;
            case 23: NATS(op.out) = NATS(op.a) * NATS(op.b); break;
            case 24: NATS(op.out) = NATS(op.a) ^ NATS(op.b); break;
            case 25: NATS(op.out) = NATS(op.a) & NATS(op.b); break;
            case 3:
                FLDS(op.out) = T::from_canonical_u32((uint32_t)NATS(op.a));
                is_fld = true;
                break;
            case 4: FLDS(op.out) = FLDS(op.a) + FLDS(op.b); is_fld = true; break;
            case 19: FLDS(op.out) = FLDS(op.a) - FLDS(op.b); is_fld = true; break;
            case 5: FLDS(op.out) = FLDS(op.a).reciprocal(); is_fld = true; break;
            case 18:
                FLDS(op.out) = NATS(op.a) ? FLDS(op.b) : FLDS(op.imm1);
                is_fld = true;
                break;
            // --- lookup ops: no wire, accumulate histogram; never a column ---
            case 6: {
                uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                atomicAdd(&range_hist[v + (1u << 16)], 1u);
                continue;
            }
            case 7: {
                uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                continue;
            }
            case 22: {
                uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                uint32_t bits = (uint32_t)NATS(op.b);
                atomicAdd(&range_hist[v + (1u << bits)], 1u);
                continue;
            }
            case 9: {
                uint32_t b = (uint32_t)(uint8_t)NATS(op.a);
                uint32_t c = (uint32_t)(uint8_t)NATS(op.b);
                atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS
                                     + WITGEN_BYTE_U8RANGE_COL], 1u);
                continue;
            }
            case 13: {
                if (NATS(op.b)) {
                    uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                    atomicAdd(&range_hist[v + (1u << 16)], 1u);
                }
                continue;
            }
            case 14: {
                if (NATS(op.b)) {
                    uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                    atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                }
                continue;
            }
            case 15: {
                if (NATS(op.imm1)) {
                    uint32_t b = (uint32_t)(uint8_t)NATS(op.a);
                    uint32_t c = (uint32_t)(uint8_t)NATS(op.b);
                    atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS
                                         + WITGEN_BYTE_U8RANGE_COL], 1u);
                }
                continue;
            }
            case 16: {
                uint32_t b = (uint32_t)(uint8_t)NATS(op.a);
                uint32_t c = (uint32_t)(uint8_t)NATS(op.b);
                uint32_t opc = (uint32_t)NATS(op.imm1);
                atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                continue;
            }
            case 17: {
                if (NATS((uint32_t)op.imm0)) {
                    uint32_t b = (uint32_t)(uint8_t)NATS(op.a);
                    uint32_t c = (uint32_t)(uint8_t)NATS(op.b);
                    uint32_t opc = (uint32_t)NATS(op.imm1);
                    atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                }
                continue;
            }
            }
            // Store-through: single-column wires go straight to the trace.
            if (op.col != 0xFFFFFFFFu) {
                trace[row + (uintptr_t)op.col * trace_height] =
                    is_fld ? FLDS(op.out) : T::from_canonical_u32((uint32_t)NATS(op.out));
            }
        }

        // Multi-column wires (census: rare/none) — written after the op loop.
        for (uint32_t i = 0; i < n_epi; ++i) {
            trace[row + (uintptr_t)epi_col[i] * trace_height] =
                T::from_canonical_u32((uint32_t)NATS(epi_slot[i]));
        }
    }
#undef NATS
#undef FLDS
}

// Streaming store-through kernel with LOCAL-memory wires: the smem variant's
// semantics at the full WITGEN_MAX_WIRES cap, for chips whose streaming footprint
// exceeds the smem tier (Keccak 69, Mul 49, SHA ~135-211 transient slots).
template <class T>
__global__ void witgen_fused_streaming_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::WitOpCSlot* ops,
    uintptr_t n_ops,
    uint32_t num_inputs,
    const uint32_t* input_slots,       // input i lives in slot input_slots[i]
    const uint32_t* input_col_idx,     // input-columns: (input index, col) pairs
    const uint32_t* input_col_col,
    uint32_t n_input_cols,
    const uint32_t* epi_slot,          // epilogue: (slot, col) pairs
    const uint32_t* epi_col,
    uint32_t n_epi,
    const uint64_t* inputs,            // row-major [n_rows][num_inputs]
    uintptr_t n_rows,
    uint32_t* range_hist,
    uint32_t* byte_hist) {
    uint64_t nat_l[WITGEN_MAX_WIRES];
    T fld_l[WITGEN_MAX_WIRES];
#define NATS(s) nat_l[s]
#define FLDS(s) fld_l[s]

    int row = blockIdx.x * blockDim.x + threadIdx.x;
    for (; row < n_rows; row += blockDim.x * gridDim.x) {
        for (uint32_t i = 0; i < num_inputs; ++i) {
            NATS(input_slots[i]) = inputs[row * num_inputs + i];
        }
        for (uint32_t i = 0; i < n_input_cols; ++i) {
            trace[row + (uintptr_t)input_col_col[i] * trace_height] =
                T::from_canonical_u32((uint32_t)inputs[row * num_inputs + input_col_idx[i]]);
        }

        for (uintptr_t k = 0; k < n_ops; ++k) {
            const sp1_gpu_sys::WitOpCSlot op = ops[k];
            bool is_fld = false;
            switch (op.tag) {
            case 0: NATS(op.out) = op.imm0; break;
            case 1: NATS(op.out) = NATS(op.a) + NATS(op.b); break;
            case 8: NATS(op.out) = NATS(op.a) - NATS(op.b); break;
            case 2: {
                uint64_t mask = (op.imm1 >= 64) ? ~0ULL : ((1ULL << op.imm1) - 1);
                NATS(op.out) = (NATS(op.a) >> op.imm0) & mask;
                break;
            }
            case 11: NATS(op.out) = (NATS(op.a) == NATS(op.b)) ? 1 : 0; break;
            case 12: NATS(op.out) = NATS(op.a) ? NATS(op.b) : NATS(op.imm1); break;
            case 20: NATS(op.out) = NATS(op.a) << NATS(op.b); break;
            case 21: NATS(op.out) = NATS(op.a) >> NATS(op.b); break;
            case 23: NATS(op.out) = NATS(op.a) * NATS(op.b); break;
            case 24: NATS(op.out) = NATS(op.a) ^ NATS(op.b); break;
            case 25: NATS(op.out) = NATS(op.a) & NATS(op.b); break;
            case 3:
                FLDS(op.out) = T::from_canonical_u32((uint32_t)NATS(op.a));
                is_fld = true;
                break;
            case 4: FLDS(op.out) = FLDS(op.a) + FLDS(op.b); is_fld = true; break;
            case 19: FLDS(op.out) = FLDS(op.a) - FLDS(op.b); is_fld = true; break;
            case 5: FLDS(op.out) = FLDS(op.a).reciprocal(); is_fld = true; break;
            case 18:
                FLDS(op.out) = NATS(op.a) ? FLDS(op.b) : FLDS(op.imm1);
                is_fld = true;
                break;
            // --- lookup ops: no wire, accumulate histogram; never a column ---
            case 6: {
                uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                atomicAdd(&range_hist[v + (1u << 16)], 1u);
                continue;
            }
            case 7: {
                uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                continue;
            }
            case 22: {
                uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                uint32_t bits = (uint32_t)NATS(op.b);
                atomicAdd(&range_hist[v + (1u << bits)], 1u);
                continue;
            }
            case 9: {
                uint32_t b = (uint32_t)(uint8_t)NATS(op.a);
                uint32_t c = (uint32_t)(uint8_t)NATS(op.b);
                atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS
                                     + WITGEN_BYTE_U8RANGE_COL], 1u);
                continue;
            }
            case 13: {
                if (NATS(op.b)) {
                    uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                    atomicAdd(&range_hist[v + (1u << 16)], 1u);
                }
                continue;
            }
            case 14: {
                if (NATS(op.b)) {
                    uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                    atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                }
                continue;
            }
            case 15: {
                if (NATS(op.imm1)) {
                    uint32_t b = (uint32_t)(uint8_t)NATS(op.a);
                    uint32_t c = (uint32_t)(uint8_t)NATS(op.b);
                    atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS
                                         + WITGEN_BYTE_U8RANGE_COL], 1u);
                }
                continue;
            }
            case 16: {
                uint32_t b = (uint32_t)(uint8_t)NATS(op.a);
                uint32_t c = (uint32_t)(uint8_t)NATS(op.b);
                uint32_t opc = (uint32_t)NATS(op.imm1);
                atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                continue;
            }
            case 17: {
                if (NATS((uint32_t)op.imm0)) {
                    uint32_t b = (uint32_t)(uint8_t)NATS(op.a);
                    uint32_t c = (uint32_t)(uint8_t)NATS(op.b);
                    uint32_t opc = (uint32_t)NATS(op.imm1);
                    atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                }
                continue;
            }
            }
            // Store-through: single-column wires go straight to the trace.
            if (op.col != 0xFFFFFFFFu) {
                trace[row + (uintptr_t)op.col * trace_height] =
                    is_fld ? FLDS(op.out) : T::from_canonical_u32((uint32_t)NATS(op.out));
            }
        }

        // Multi-column wires (census: rare/none) — written after the op loop.
        for (uint32_t i = 0; i < n_epi; ++i) {
            trace[row + (uintptr_t)epi_col[i] * trace_height] =
                T::from_canonical_u32((uint32_t)NATS(epi_slot[i]));
        }
    }
#undef NATS
#undef FLDS
}

namespace sp1_gpu_sys {
extern KernelPtr witgen_fused_streaming_smem_koala_bear_kernel() {
    return (KernelPtr)::witgen_fused_streaming_smem_kernel<kb31_t>;
}
extern KernelPtr witgen_fused_streaming_koala_bear_kernel() {
    return (KernelPtr)::witgen_fused_streaming_kernel<kb31_t>;
}
extern KernelPtr witgen_fused_slots_koala_bear_kernel() {
    return (KernelPtr)::witgen_fused_slots_kernel<kb31_t>;
}
extern KernelPtr witgen_interp_slots_koala_bear_kernel() {
    return (KernelPtr)::witgen_interp_slots_kernel<kb31_t>;
}
extern KernelPtr witgen_lookup_slots_koala_bear_kernel() {
    return (KernelPtr)::witgen_lookup_slots_kernel;
}
extern KernelPtr witgen_interp_koala_bear_kernel() {
    return (KernelPtr)::witgen_interp_kernel<kb31_t>;
}
extern KernelPtr hist_to_trace_koala_bear_kernel() {
    return (KernelPtr)::hist_to_trace_kernel<kb31_t>;
}
extern KernelPtr hist_trace_scatter_koala_bear_kernel() {
    return (KernelPtr)::hist_trace_scatter_kernel;
}
extern KernelPtr witgen_lookup_koala_bear_kernel() {
    return (KernelPtr)::witgen_lookup_kernel;
}
extern KernelPtr witgen_fused_koala_bear_kernel() {
    return (KernelPtr)::witgen_fused_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
