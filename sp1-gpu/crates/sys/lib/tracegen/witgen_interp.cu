// Generic witness-generation interpreter kernels — the device backend of the
// witgen IR (see crates/core/machine/src/air/WITGEN-IR.md at the repo root).
//
// Unlike the per-chip tracegen kernels (e.g. recursion/alu_base.cu), each kernel
// here interprets a recorded op-DAG (`sp1_gpu_sys::WitOpC[]` / `WitOpCSlot[]`),
// one thread per event row. The op-tag census — 16 value ops + 9 lookup ops over
// the cbindgen-pinned `WitTag` enum (values 0..=25, 10 unassigned) — and the
// per-tag field-overloading rules are documented on `WitOpC` in
// crates/core/machine/src/air/witness_record.rs. Every kernel switch below must
// cover exactly those tags (adding an IR op = one `case` per kernel switch, 8
// sites; a missed site hits that switch's trapping `default:`), and each kernel
// is a port of a CPU reference interpreter in that file, validated bit-identical
// before the CUDA port.
//
// Kernel families (launchers: sp1-gpu/crates/tracegen/src/riscv/mod.rs):
//
// 1. SSA family (`WitOpC`; per-thread `nat[wc++]`, one cell per value op, cap
//    WITGEN_MAX_WIRES):
//      witgen_interp_kernel  — columns only   (port of `interpret_c_columns`)
//      witgen_lookup_kernel  — histograms only (port of `interpret_c_lookups`)
//      witgen_fused_kernel   — columns + histograms in one pass
//    Production uses witgen_interp_kernel for device chips whose dependencies
//    must stay on host (MemoryLocal/MemoryGlobal*/Syscall*); the SSA fused form
//    runs only under the AR_WITGEN_SLOTS=0 kill-switch.
//
// 2. Slot family (`WitOpCSlot`; register-allocated `nat[op.out]`, column wires
//    pinned live for an end readout; port of `interpret_c_slots_columns`):
//      witgen_interp_slots_kernel / witgen_lookup_slots_kernel /
//      witgen_fused_slots_kernel
//    witgen_fused_slots_kernel is the production FALLBACK tier when the
//    streaming lowering cannot run (footprint > WITGEN_MAX_WIRES, or a non-empty
//    multi-column epilogue).
//
// 3. Streaming family (store-through: `op.col != MAX` writes the wire to the
//    trace at production, freeing its slot; port of
//    `interpret_c_slots_streaming_columns`) — the PRODUCTION DEFAULT, tiered by
//    the streaming footprint `streaming_max`:
//      streaming_max <= WITGEN_SMEM_CAP  -> witgen_fused_streaming_smem_kernel
//                                           (__shared__ wires)
//      streaming_max <= WITGEN_MAX_WIRES -> witgen_fused_streaming_kernel
//                                           (local wires)
//      otherwise                         -> pinned fallback (family 2).
//
// 4. Byte/Range table materialization: hist_to_trace_kernel +
//    hist_trace_scatter_kernel build the deferred lookup-table traces directly
//    from the shard histograms (the table trace IS the histogram).
//
// Lookup ops atomicAdd into two shard-level dense histograms (Range: 1<<17 rows;
// Byte: (1<<16) x WITGEN_NUM_BYTE_MULT_COLS), allocated and zeroed ONCE per shard
// by the prover (`new_byte_histograms`) — never per chunk (the iter-004 lesson).

#include "sp1-gpu-cbindgen.hpp"

#include "fields/kb31_t.cuh"

// Op tags: cbindgen-pinned from `WitTag` in
// crates/core/machine/src/air/witness_record.rs — the switches below consume the
// SAME enum the Rust lowerings emit, so the two sides cannot drift. An op value
// outside the enum (an unported/garbage tag) hits each switch's `default:`
// __trap() — loud device abort instead of silently skipping the op and shifting
// every subsequent wire.
using WT = sp1_gpu_sys::WitTag;

// Per-thread wire-array capacity: max wires (inputs + value ops) on the SSA path,
// max live slots on the slot/streaming paths. cbindgen-pinned from
// crates/core/machine/src/air/witness_record.rs (the host asserts every lowered
// program fits before launching).
constexpr uint32_t WITGEN_MAX_WIRES = (uint32_t)sp1_gpu_sys::WITGEN_MAX_WIRES;

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
    uintptr_t row = blockIdx.x * blockDim.x + threadIdx.x;
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
            case WT::ConstNat:
                nat[wc] = op.imm0;
                is_field[wc] = false;
                ++wc;
                break;
            case WT::WrappingAdd: // u64 wraps naturally
                nat[wc] = nat[op.a] + nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case WT::WrappingSub: // u64 wraps naturally
                nat[wc] = nat[op.a] - nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case WT::Bits: { // (src >> offset) & ((1<<width)-1)
                uint64_t mask = (op.imm1 >= 64) ? ~0ULL : ((1ULL << op.imm1) - 1);
                nat[wc] = (nat[op.a] >> op.imm0) & mask;
                is_field[wc] = false;
                ++wc;
                break;
            }
            case WT::Eq: // -> 0/1
                nat[wc] = (nat[op.a] == nat[op.b]) ? 1 : 0;
                is_field[wc] = false;
                ++wc;
                break;
            case WT::Select: // cond=a, then-wire=b, else-wire=imm1
                nat[wc] = nat[op.a] ? nat[op.b] : nat[op.imm1];
                is_field[wc] = false;
                ++wc;
                break;
            case WT::Shl: // a << shift
                nat[wc] = nat[op.a] << nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case WT::Shr: // a >> shift
                nat[wc] = nat[op.a] >> nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case WT::Mul: // a * b (wrapping)
                nat[wc] = nat[op.a] * nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case WT::Xor:
                nat[wc] = nat[op.a] ^ nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case WT::And:
                nat[wc] = nat[op.a] & nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case WT::NatToField:
                fld[wc] = T::from_canonical_u32((uint32_t)nat[op.a]);
                is_field[wc] = true;
                ++wc;
                break;
            case WT::FieldAdd:
                fld[wc] = fld[op.a] + fld[op.b];
                is_field[wc] = true;
                ++wc;
                break;
            case WT::FieldSub:
                fld[wc] = fld[op.a] - fld[op.b];
                is_field[wc] = true;
                ++wc;
                break;
            case WT::FieldInverse:
                fld[wc] = fld[op.a].reciprocal();
                is_field[wc] = true;
                ++wc;
                break;
            case WT::FieldSelect: // cond=a (nat), then-field=b, else-field=imm1
                fld[wc] = nat[op.a] ? fld[op.b] : fld[op.imm1];
                is_field[wc] = true;
                ++wc;
                break;
            // Lookup ops: no wire — skipped by this columns-only kernel.
            case WT::U16RangeCheck:
            case WT::BitRangeCheck:
            case WT::U8RangeCheck:
            case WT::U16RangeCheckGuarded:
            case WT::BitRangeCheckGuarded:
            case WT::U8RangeCheckGuarded:
            case WT::ByteLookup:
            case WT::ByteLookupGuarded:
            case WT::BitRangeCheckVar:
                break;
            default:
                // Unknown/unported tag: silently skipping would shift every
                // subsequent wire (silent corruption) — abort the kernel instead.
                __trap();
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
// (tags 6/7/9, guarded 13/14/15, byte-table 16/17, var-width 22) into two
// shard-level dense multiplicity tables via `atomicAdd`. The table index
// conventions match the consumer chips exactly (see range/trace.rs and
// bytes/trace.rs); the CPU reference is `interpret_c_lookups` in
// crates/core/machine/src/air/witness_record.rs.
//
// Integer-only: lookups read only Nat wires, so field-producing ops (tags
// 3/4/5/18/19) write a placeholder to keep wire ids aligned with the column
// interpreter.
//
// Multiplicities are u32 counts (native atomicAdd). One shard-level histogram pair,
// allocated/zeroed once by the host (heed iter-004: NO per-chunk dense arrays).
// Global atomics for now (correctness); per-block privatization is a perf follow-up.

// Byte-table multiplicity columns (MUST MATCH `NUM_BYTE_MULT_COLS` in
// crates/core/machine/src/bytes/columns.rs) and the U8Range opcode index (MUST
// MATCH `sp1_core_executor::ByteOpcode::U8Range as usize`).
#define WITGEN_NUM_BYTE_MULT_COLS 6
#define WITGEN_BYTE_U8RANGE_COL 3

// Two histogram indices are per-row DATA rather than program constants: the
// var-width range check's `bits` (tag 22) and the byte lookup's opcode (tags
// 16/17). In-contract programs keep `bits <= 16` and `opc <
// WITGEN_NUM_BYTE_MULT_COLS` (executor invariants; the CPU reference
// `interpret_c_lookups` has the same exposure) — every emit site guards them
// anyway, so a violated invariant DROPS the count (surfacing as a LogUp
// multiset mismatch at verification) instead of scribbling device memory.

__global__ void witgen_lookup_kernel(
    const sp1_gpu_sys::WitOpC* ops,    // the recorded op-DAG
    uintptr_t n_ops,
    uint32_t num_inputs,
    const uint64_t* inputs,            // row-major [n_rows][num_inputs]
    uintptr_t n_rows,
    uint32_t* range_hist,              // Range chip table, len 1<<17
    uint32_t* byte_hist) {             // Byte chip table, len (1<<16)*NUM_BYTE_MULT_COLS
    uintptr_t row = blockIdx.x * blockDim.x + threadIdx.x;
    for (; row < n_rows; row += blockDim.x * gridDim.x) {
        uint64_t nat[WITGEN_MAX_WIRES];

        uint32_t wc = 0;
        for (uint32_t i = 0; i < num_inputs; ++i) {
            nat[wc++] = inputs[row * num_inputs + i];
        }

        for (uintptr_t k = 0; k < n_ops; ++k) {
            const sp1_gpu_sys::WitOpC op = ops[k];
            switch (op.tag) {
            case WT::ConstNat:
                nat[wc++] = op.imm0;
                break;
            case WT::WrappingAdd:
                nat[wc++] = nat[op.a] + nat[op.b];
                break;
            case WT::WrappingSub:
                nat[wc++] = nat[op.a] - nat[op.b];
                break;
            case WT::Bits: {
                uint64_t mask = (op.imm1 >= 64) ? ~0ULL : ((1ULL << op.imm1) - 1);
                nat[wc++] = (nat[op.a] >> op.imm0) & mask;
                break;
            }
            case WT::Eq:
                nat[wc++] = (nat[op.a] == nat[op.b]) ? 1 : 0;
                break;
            case WT::Select:
                nat[wc++] = nat[op.a] ? nat[op.b] : nat[op.imm1];
                break;
            case WT::Shl:
                nat[wc++] = nat[op.a] << nat[op.b];
                break;
            case WT::Shr:
                nat[wc++] = nat[op.a] >> nat[op.b];
                break;
            case WT::Mul:
                nat[wc++] = nat[op.a] * nat[op.b];
                break;
            case WT::Xor:
                nat[wc++] = nat[op.a] ^ nat[op.b];
                break;
            case WT::And:
                nat[wc++] = nat[op.a] & nat[op.b];
                break;
            case WT::NatToField:
            case WT::FieldAdd:
            case WT::FieldInverse:
            case WT::FieldSelect:
            case WT::FieldSub:
                nat[wc++] = 0; // field wire: placeholder (never read by a lookup)
                break;
            case WT::U16RangeCheck: { // -> {Range, a: v, bits: 16}
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                atomicAdd(&range_hist[v + (1u << 16)], 1u);
                break;
            }
            case WT::BitRangeCheck: { // -> {Range, a: v, bits: imm0}
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                break;
            }
            case WT::BitRangeCheckVar: { // -> {Range, a: v, bits: nat[op.b]}
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                uint32_t bits = (uint32_t)nat[op.b];
                if (bits <= 16)
                    atomicAdd(&range_hist[v + (1u << bits)], 1u);
                break;
            }
            case WT::U8RangeCheck: { // -> {U8Range, b: nat[a], c: nat[b]}
                uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                uint32_t r = (b << 8) + c;
                atomicAdd(&byte_hist[r * WITGEN_NUM_BYTE_MULT_COLS + WITGEN_BYTE_U8RANGE_COL], 1u);
                break;
            }
            // Guarded lookups (per-row branches): emit only if the guard wire != 0.
            case WT::U16RangeCheckGuarded: { // guard wire in `b`
                if (nat[op.b]) {
                    uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                    atomicAdd(&range_hist[v + (1u << 16)], 1u);
                }
                break;
            }
            case WT::BitRangeCheckGuarded: { // guard wire in `b`, bits in imm0
                if (nat[op.b]) {
                    uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                    atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                }
                break;
            }
            case WT::U8RangeCheckGuarded: { // guard wire in `imm1`
                if (nat[op.imm1]) {
                    uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                    uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                    uint32_t r = (b << 8) + c;
                    atomicAdd(
                        &byte_hist[r * WITGEN_NUM_BYTE_MULT_COLS + WITGEN_BYTE_U8RANGE_COL], 1u);
                }
                break;
            }
            case WT::ByteLookup: { // b in a, c in b, opcode in imm1 -> index (b,c,opcode)
                uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                uint32_t opc = (uint32_t)nat[op.imm1];
                if (opc < WITGEN_NUM_BYTE_MULT_COLS)
                    atomicAdd(
                        &byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                break;
            }
            case WT::ByteLookupGuarded: { // guard wire in imm0
                if (nat[(uintptr_t)op.imm0]) {
                    uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                    uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                    uint32_t opc = (uint32_t)nat[op.imm1];
                    if (opc < WITGEN_NUM_BYTE_MULT_COLS)
                        atomicAdd(
                            &byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                }
                break;
            }
            default:
                // Unknown/unported tag: silently skipping would shift every
                // subsequent wire (silent corruption) — abort the kernel instead.
                __trap();
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
    uintptr_t row = blockIdx.x * blockDim.x + threadIdx.x;
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
            case WT::ConstNat:
                nat[wc] = op.imm0;
                is_field[wc] = false;
                ++wc;
                break;
            case WT::WrappingAdd:
                nat[wc] = nat[op.a] + nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case WT::WrappingSub:
                nat[wc] = nat[op.a] - nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case WT::Bits: {
                uint64_t mask = (op.imm1 >= 64) ? ~0ULL : ((1ULL << op.imm1) - 1);
                nat[wc] = (nat[op.a] >> op.imm0) & mask;
                is_field[wc] = false;
                ++wc;
                break;
            }
            case WT::Eq:
                nat[wc] = (nat[op.a] == nat[op.b]) ? 1 : 0;
                is_field[wc] = false;
                ++wc;
                break;
            case WT::Select:
                nat[wc] = nat[op.a] ? nat[op.b] : nat[op.imm1];
                is_field[wc] = false;
                ++wc;
                break;
            case WT::Shl:
                nat[wc] = nat[op.a] << nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case WT::Shr:
                nat[wc] = nat[op.a] >> nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case WT::Mul:
                nat[wc] = nat[op.a] * nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case WT::Xor:
                nat[wc] = nat[op.a] ^ nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case WT::And:
                nat[wc] = nat[op.a] & nat[op.b];
                is_field[wc] = false;
                ++wc;
                break;
            case WT::NatToField:
                fld[wc] = T::from_canonical_u32((uint32_t)nat[op.a]);
                is_field[wc] = true;
                ++wc;
                break;
            case WT::FieldAdd:
                fld[wc] = fld[op.a] + fld[op.b];
                is_field[wc] = true;
                ++wc;
                break;
            case WT::FieldSub:
                fld[wc] = fld[op.a] - fld[op.b];
                is_field[wc] = true;
                ++wc;
                break;
            case WT::FieldInverse:
                fld[wc] = fld[op.a].reciprocal();
                is_field[wc] = true;
                ++wc;
                break;
            case WT::FieldSelect:
                fld[wc] = nat[op.a] ? fld[op.b] : fld[op.imm1];
                is_field[wc] = true;
                ++wc;
                break;
            // --- lookup ops: no wire, accumulate histogram (from witgen_lookup_kernel) ---
            case WT::U16RangeCheck: {
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                atomicAdd(&range_hist[v + (1u << 16)], 1u);
                break;
            }
            case WT::BitRangeCheck: {
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                break;
            }
            case WT::BitRangeCheckVar: {
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                uint32_t bits = (uint32_t)nat[op.b];
                if (bits <= 16)
                    atomicAdd(&range_hist[v + (1u << bits)], 1u);
                break;
            }
            case WT::U8RangeCheck: {
                uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                uint32_t r = (b << 8) + c;
                atomicAdd(&byte_hist[r * WITGEN_NUM_BYTE_MULT_COLS + WITGEN_BYTE_U8RANGE_COL], 1u);
                break;
            }
            case WT::U16RangeCheckGuarded: {
                if (nat[op.b]) {
                    uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                    atomicAdd(&range_hist[v + (1u << 16)], 1u);
                }
                break;
            }
            case WT::BitRangeCheckGuarded: {
                if (nat[op.b]) {
                    uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                    atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                }
                break;
            }
            case WT::U8RangeCheckGuarded: {
                if (nat[op.imm1]) {
                    uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                    uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                    uint32_t r = (b << 8) + c;
                    atomicAdd(
                        &byte_hist[r * WITGEN_NUM_BYTE_MULT_COLS + WITGEN_BYTE_U8RANGE_COL], 1u);
                }
                break;
            }
            case WT::ByteLookup: {
                uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                uint32_t opc = (uint32_t)nat[op.imm1];
                if (opc < WITGEN_NUM_BYTE_MULT_COLS)
                    atomicAdd(
                        &byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                break;
            }
            case WT::ByteLookupGuarded: {
                if (nat[(uintptr_t)op.imm0]) {
                    uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                    uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                    uint32_t opc = (uint32_t)nat[op.imm1];
                    if (opc < WITGEN_NUM_BYTE_MULT_COLS)
                        atomicAdd(
                            &byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                }
                break;
            }
            default:
                // Unknown/unported tag: silently skipping would shift every
                // subsequent wire (silent corruption) — abort the kernel instead.
                __trap();
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
    const uint32_t* idxs, // max index < 2^18 (Range hist rows) — u32 halves the upload (H4)
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
    uintptr_t row = blockIdx.x * blockDim.x + threadIdx.x;
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
            case WT::ConstNat:
                nat[op.out] = op.imm0;
                is_field[op.out] = false;
                break;
            case WT::WrappingAdd:
                nat[op.out] = nat[op.a] + nat[op.b];
                is_field[op.out] = false;
                break;
            case WT::WrappingSub:
                nat[op.out] = nat[op.a] - nat[op.b];
                is_field[op.out] = false;
                break;
            case WT::Bits: {
                uint64_t mask = (op.imm1 >= 64) ? ~0ULL : ((1ULL << op.imm1) - 1);
                nat[op.out] = (nat[op.a] >> op.imm0) & mask;
                is_field[op.out] = false;
                break;
            }
            case WT::Eq:
                nat[op.out] = (nat[op.a] == nat[op.b]) ? 1 : 0;
                is_field[op.out] = false;
                break;
            case WT::Select:
                nat[op.out] = nat[op.a] ? nat[op.b] : nat[op.imm1];
                is_field[op.out] = false;
                break;
            case WT::Shl:
                nat[op.out] = nat[op.a] << nat[op.b];
                is_field[op.out] = false;
                break;
            case WT::Shr:
                nat[op.out] = nat[op.a] >> nat[op.b];
                is_field[op.out] = false;
                break;
            case WT::Mul:
                nat[op.out] = nat[op.a] * nat[op.b];
                is_field[op.out] = false;
                break;
            case WT::Xor:
                nat[op.out] = nat[op.a] ^ nat[op.b];
                is_field[op.out] = false;
                break;
            case WT::And:
                nat[op.out] = nat[op.a] & nat[op.b];
                is_field[op.out] = false;
                break;
            case WT::NatToField:
                fld[op.out] = T::from_canonical_u32((uint32_t)nat[op.a]);
                is_field[op.out] = true;
                break;
            case WT::FieldAdd:
                fld[op.out] = fld[op.a] + fld[op.b];
                is_field[op.out] = true;
                break;
            case WT::FieldSub:
                fld[op.out] = fld[op.a] - fld[op.b];
                is_field[op.out] = true;
                break;
            case WT::FieldInverse:
                fld[op.out] = fld[op.a].reciprocal();
                is_field[op.out] = true;
                break;
            case WT::FieldSelect:
                fld[op.out] = nat[op.a] ? fld[op.b] : fld[op.imm1];
                is_field[op.out] = true;
                break;
            case WT::U16RangeCheck:  // lookups: no wire
            case WT::BitRangeCheck:
            case WT::U8RangeCheck:
            case WT::U16RangeCheckGuarded:
            case WT::BitRangeCheckGuarded:
            case WT::U8RangeCheckGuarded:
            case WT::ByteLookup:
            case WT::ByteLookupGuarded:
            case WT::BitRangeCheckVar:
                break;
            default:
                // Unknown/unported tag: silently skipping would shift every
                // subsequent wire (silent corruption) — abort the kernel instead.
                __trap();
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
    uintptr_t row = blockIdx.x * blockDim.x + threadIdx.x;
    for (; row < n_rows; row += blockDim.x * gridDim.x) {
        uint64_t nat[WITGEN_MAX_WIRES];

        for (uint32_t i = 0; i < num_inputs; ++i) {
            nat[input_slots[i]] = inputs[row * num_inputs + i];
        }

        for (uintptr_t k = 0; k < n_ops; ++k) {
            const sp1_gpu_sys::WitOpCSlot op = ops[k];
            switch (op.tag) {
            case WT::ConstNat: nat[op.out] = op.imm0; break;
            case WT::WrappingAdd: nat[op.out] = nat[op.a] + nat[op.b]; break;
            case WT::WrappingSub: nat[op.out] = nat[op.a] - nat[op.b]; break;
            case WT::Bits: {
                uint64_t mask = (op.imm1 >= 64) ? ~0ULL : ((1ULL << op.imm1) - 1);
                nat[op.out] = (nat[op.a] >> op.imm0) & mask;
                break;
            }
            case WT::Eq: nat[op.out] = (nat[op.a] == nat[op.b]) ? 1 : 0; break;
            case WT::Select: nat[op.out] = nat[op.a] ? nat[op.b] : nat[op.imm1]; break;
            case WT::Shl: nat[op.out] = nat[op.a] << nat[op.b]; break;
            case WT::Shr: nat[op.out] = nat[op.a] >> nat[op.b]; break;
            case WT::Mul: nat[op.out] = nat[op.a] * nat[op.b]; break;
            case WT::Xor: nat[op.out] = nat[op.a] ^ nat[op.b]; break;
            case WT::And: nat[op.out] = nat[op.a] & nat[op.b]; break;
            case WT::NatToField:  // field ops: placeholder (never read by a lookup)
            case WT::FieldAdd:
            case WT::FieldInverse:
            case WT::FieldSelect:
            case WT::FieldSub:
                nat[op.out] = 0;
                break;
            case WT::U16RangeCheck: {
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                atomicAdd(&range_hist[v + (1u << 16)], 1u);
                break;
            }
            case WT::BitRangeCheck: {
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                break;
            }
            case WT::BitRangeCheckVar: {
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                uint32_t bits = (uint32_t)nat[op.b];
                if (bits <= 16)
                    atomicAdd(&range_hist[v + (1u << bits)], 1u);
                break;
            }
            case WT::U8RangeCheck: {
                uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                uint32_t r = (b << 8) + c;
                atomicAdd(&byte_hist[r * WITGEN_NUM_BYTE_MULT_COLS + WITGEN_BYTE_U8RANGE_COL], 1u);
                break;
            }
            case WT::U16RangeCheckGuarded: {
                if (nat[op.b]) {
                    uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                    atomicAdd(&range_hist[v + (1u << 16)], 1u);
                }
                break;
            }
            case WT::BitRangeCheckGuarded: {
                if (nat[op.b]) {
                    uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                    atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                }
                break;
            }
            case WT::U8RangeCheckGuarded: {
                if (nat[op.imm1]) {
                    uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                    uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                    uint32_t r = (b << 8) + c;
                    atomicAdd(
                        &byte_hist[r * WITGEN_NUM_BYTE_MULT_COLS + WITGEN_BYTE_U8RANGE_COL], 1u);
                }
                break;
            }
            case WT::ByteLookup: {
                uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                uint32_t opc = (uint32_t)nat[op.imm1];
                if (opc < WITGEN_NUM_BYTE_MULT_COLS)
                    atomicAdd(
                        &byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                break;
            }
            case WT::ByteLookupGuarded: {
                if (nat[(uintptr_t)op.imm0]) {
                    uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                    uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                    uint32_t opc = (uint32_t)nat[op.imm1];
                    if (opc < WITGEN_NUM_BYTE_MULT_COLS)
                        atomicAdd(
                            &byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                }
                break;
            }
            default:
                // Unknown/unported tag: silently skipping would shift every
                // subsequent wire (silent corruption) — abort the kernel instead.
                __trap();
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
    uintptr_t row = blockIdx.x * blockDim.x + threadIdx.x;
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
            case WT::ConstNat:
                nat[op.out] = op.imm0;
                is_field[op.out] = false;
                break;
            case WT::WrappingAdd:
                nat[op.out] = nat[op.a] + nat[op.b];
                is_field[op.out] = false;
                break;
            case WT::WrappingSub:
                nat[op.out] = nat[op.a] - nat[op.b];
                is_field[op.out] = false;
                break;
            case WT::Bits: {
                uint64_t mask = (op.imm1 >= 64) ? ~0ULL : ((1ULL << op.imm1) - 1);
                nat[op.out] = (nat[op.a] >> op.imm0) & mask;
                is_field[op.out] = false;
                break;
            }
            case WT::Eq:
                nat[op.out] = (nat[op.a] == nat[op.b]) ? 1 : 0;
                is_field[op.out] = false;
                break;
            case WT::Select:
                nat[op.out] = nat[op.a] ? nat[op.b] : nat[op.imm1];
                is_field[op.out] = false;
                break;
            case WT::Shl:
                nat[op.out] = nat[op.a] << nat[op.b];
                is_field[op.out] = false;
                break;
            case WT::Shr:
                nat[op.out] = nat[op.a] >> nat[op.b];
                is_field[op.out] = false;
                break;
            case WT::Mul:
                nat[op.out] = nat[op.a] * nat[op.b];
                is_field[op.out] = false;
                break;
            case WT::Xor:
                nat[op.out] = nat[op.a] ^ nat[op.b];
                is_field[op.out] = false;
                break;
            case WT::And:
                nat[op.out] = nat[op.a] & nat[op.b];
                is_field[op.out] = false;
                break;
            case WT::NatToField:
                fld[op.out] = T::from_canonical_u32((uint32_t)nat[op.a]);
                is_field[op.out] = true;
                break;
            case WT::FieldAdd:
                fld[op.out] = fld[op.a] + fld[op.b];
                is_field[op.out] = true;
                break;
            case WT::FieldSub:
                fld[op.out] = fld[op.a] - fld[op.b];
                is_field[op.out] = true;
                break;
            case WT::FieldInverse:
                fld[op.out] = fld[op.a].reciprocal();
                is_field[op.out] = true;
                break;
            case WT::FieldSelect:
                fld[op.out] = nat[op.a] ? fld[op.b] : fld[op.imm1];
                is_field[op.out] = true;
                break;
            // --- lookup ops (from witgen_lookup_slots_kernel) ---
            case WT::U16RangeCheck: {
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                atomicAdd(&range_hist[v + (1u << 16)], 1u);
                break;
            }
            case WT::BitRangeCheck: {
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                break;
            }
            case WT::BitRangeCheckVar: {
                uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                uint32_t bits = (uint32_t)nat[op.b];
                if (bits <= 16)
                    atomicAdd(&range_hist[v + (1u << bits)], 1u);
                break;
            }
            case WT::U8RangeCheck: {
                uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                uint32_t r = (b << 8) + c;
                atomicAdd(&byte_hist[r * WITGEN_NUM_BYTE_MULT_COLS + WITGEN_BYTE_U8RANGE_COL], 1u);
                break;
            }
            case WT::U16RangeCheckGuarded: {
                if (nat[op.b]) {
                    uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                    atomicAdd(&range_hist[v + (1u << 16)], 1u);
                }
                break;
            }
            case WT::BitRangeCheckGuarded: {
                if (nat[op.b]) {
                    uint32_t v = (uint32_t)(uint16_t)nat[op.a];
                    atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                }
                break;
            }
            case WT::U8RangeCheckGuarded: {
                if (nat[op.imm1]) {
                    uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                    uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                    uint32_t r = (b << 8) + c;
                    atomicAdd(
                        &byte_hist[r * WITGEN_NUM_BYTE_MULT_COLS + WITGEN_BYTE_U8RANGE_COL], 1u);
                }
                break;
            }
            case WT::ByteLookup: {
                uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                uint32_t opc = (uint32_t)nat[op.imm1];
                if (opc < WITGEN_NUM_BYTE_MULT_COLS)
                    atomicAdd(
                        &byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                break;
            }
            case WT::ByteLookupGuarded: {
                if (nat[(uintptr_t)op.imm0]) {
                    uint32_t b = (uint32_t)(uint8_t)nat[op.a];
                    uint32_t c = (uint32_t)(uint8_t)nat[op.b];
                    uint32_t opc = (uint32_t)nat[op.imm1];
                    if (opc < WITGEN_NUM_BYTE_MULT_COLS)
                        atomicAdd(
                            &byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                }
                break;
            }
            default:
                // Unknown/unported tag: silently skipping would shift every
                // subsequent wire (silent corruption) — abort the kernel instead.
                __trap();
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
//
// Sizing (tuned on RTX 4090 / Ada, iter-073): CAP 24 x BLOCK 64 threads x
// (8B nat + 4B kb31_t fld) = 18 KiB shared memory per block — comfortably within
// the 48 KiB default per-block limit while covering 15/20 of the then-ported
// chips' streaming footprints. Both values are cbindgen-pinned from
// crates/core/machine/src/air/witness_record.rs (shared with the Rust launcher):
// the kernel's __shared__ arrays are statically sized by CAP x BLOCK, so a larger
// host block would alias rows and a larger host cap would overflow the arrays.
constexpr uint32_t WITGEN_SMEM_CAP = sp1_gpu_sys::WITGEN_SMEM_CAP;
constexpr uint32_t WITGEN_SMEM_BLOCK = (uint32_t)sp1_gpu_sys::WITGEN_SMEM_BLOCK;

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

    uintptr_t row = blockIdx.x * blockDim.x + threadIdx.x;
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
            case WT::ConstNat: NATS(op.out) = op.imm0; break;
            case WT::WrappingAdd: NATS(op.out) = NATS(op.a) + NATS(op.b); break;
            case WT::WrappingSub: NATS(op.out) = NATS(op.a) - NATS(op.b); break;
            case WT::Bits: {
                uint64_t mask = (op.imm1 >= 64) ? ~0ULL : ((1ULL << op.imm1) - 1);
                NATS(op.out) = (NATS(op.a) >> op.imm0) & mask;
                break;
            }
            case WT::Eq: NATS(op.out) = (NATS(op.a) == NATS(op.b)) ? 1 : 0; break;
            case WT::Select: NATS(op.out) = NATS(op.a) ? NATS(op.b) : NATS(op.imm1); break;
            case WT::Shl: NATS(op.out) = NATS(op.a) << NATS(op.b); break;
            case WT::Shr: NATS(op.out) = NATS(op.a) >> NATS(op.b); break;
            case WT::Mul: NATS(op.out) = NATS(op.a) * NATS(op.b); break;
            case WT::Xor: NATS(op.out) = NATS(op.a) ^ NATS(op.b); break;
            case WT::And: NATS(op.out) = NATS(op.a) & NATS(op.b); break;
            case WT::NatToField:
                FLDS(op.out) = T::from_canonical_u32((uint32_t)NATS(op.a));
                is_fld = true;
                break;
            case WT::FieldAdd: FLDS(op.out) = FLDS(op.a) + FLDS(op.b); is_fld = true; break;
            case WT::FieldSub: FLDS(op.out) = FLDS(op.a) - FLDS(op.b); is_fld = true; break;
            case WT::FieldInverse: FLDS(op.out) = FLDS(op.a).reciprocal(); is_fld = true; break;
            case WT::FieldSelect:
                FLDS(op.out) = NATS(op.a) ? FLDS(op.b) : FLDS(op.imm1);
                is_fld = true;
                break;
            // --- lookup ops: no wire, accumulate histogram; never a column ---
            case WT::U16RangeCheck: {
                uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                atomicAdd(&range_hist[v + (1u << 16)], 1u);
                continue;
            }
            case WT::BitRangeCheck: {
                uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                continue;
            }
            case WT::BitRangeCheckVar: {
                uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                uint32_t bits = (uint32_t)NATS(op.b);
                if (bits <= 16)
                    atomicAdd(&range_hist[v + (1u << bits)], 1u);
                continue;
            }
            case WT::U8RangeCheck: {
                uint32_t b = (uint32_t)(uint8_t)NATS(op.a);
                uint32_t c = (uint32_t)(uint8_t)NATS(op.b);
                atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS
                                     + WITGEN_BYTE_U8RANGE_COL], 1u);
                continue;
            }
            case WT::U16RangeCheckGuarded: {
                if (NATS(op.b)) {
                    uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                    atomicAdd(&range_hist[v + (1u << 16)], 1u);
                }
                continue;
            }
            case WT::BitRangeCheckGuarded: {
                if (NATS(op.b)) {
                    uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                    atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                }
                continue;
            }
            case WT::U8RangeCheckGuarded: {
                if (NATS(op.imm1)) {
                    uint32_t b = (uint32_t)(uint8_t)NATS(op.a);
                    uint32_t c = (uint32_t)(uint8_t)NATS(op.b);
                    atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS
                                         + WITGEN_BYTE_U8RANGE_COL], 1u);
                }
                continue;
            }
            case WT::ByteLookup: {
                uint32_t b = (uint32_t)(uint8_t)NATS(op.a);
                uint32_t c = (uint32_t)(uint8_t)NATS(op.b);
                uint32_t opc = (uint32_t)NATS(op.imm1);
                if (opc < WITGEN_NUM_BYTE_MULT_COLS)
                    atomicAdd(
                        &byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                continue;
            }
            case WT::ByteLookupGuarded: {
                if (NATS((uint32_t)op.imm0)) {
                    uint32_t b = (uint32_t)(uint8_t)NATS(op.a);
                    uint32_t c = (uint32_t)(uint8_t)NATS(op.b);
                    uint32_t opc = (uint32_t)NATS(op.imm1);
                    if (opc < WITGEN_NUM_BYTE_MULT_COLS)
                        atomicAdd(
                            &byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                }
                continue;
            }
            default:
                // Unknown/unported tag: silently skipping would shift every
                // subsequent wire (silent corruption) — abort the kernel instead.
                __trap();
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

    uintptr_t row = blockIdx.x * blockDim.x + threadIdx.x;
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
            case WT::ConstNat: NATS(op.out) = op.imm0; break;
            case WT::WrappingAdd: NATS(op.out) = NATS(op.a) + NATS(op.b); break;
            case WT::WrappingSub: NATS(op.out) = NATS(op.a) - NATS(op.b); break;
            case WT::Bits: {
                uint64_t mask = (op.imm1 >= 64) ? ~0ULL : ((1ULL << op.imm1) - 1);
                NATS(op.out) = (NATS(op.a) >> op.imm0) & mask;
                break;
            }
            case WT::Eq: NATS(op.out) = (NATS(op.a) == NATS(op.b)) ? 1 : 0; break;
            case WT::Select: NATS(op.out) = NATS(op.a) ? NATS(op.b) : NATS(op.imm1); break;
            case WT::Shl: NATS(op.out) = NATS(op.a) << NATS(op.b); break;
            case WT::Shr: NATS(op.out) = NATS(op.a) >> NATS(op.b); break;
            case WT::Mul: NATS(op.out) = NATS(op.a) * NATS(op.b); break;
            case WT::Xor: NATS(op.out) = NATS(op.a) ^ NATS(op.b); break;
            case WT::And: NATS(op.out) = NATS(op.a) & NATS(op.b); break;
            case WT::NatToField:
                FLDS(op.out) = T::from_canonical_u32((uint32_t)NATS(op.a));
                is_fld = true;
                break;
            case WT::FieldAdd: FLDS(op.out) = FLDS(op.a) + FLDS(op.b); is_fld = true; break;
            case WT::FieldSub: FLDS(op.out) = FLDS(op.a) - FLDS(op.b); is_fld = true; break;
            case WT::FieldInverse: FLDS(op.out) = FLDS(op.a).reciprocal(); is_fld = true; break;
            case WT::FieldSelect:
                FLDS(op.out) = NATS(op.a) ? FLDS(op.b) : FLDS(op.imm1);
                is_fld = true;
                break;
            // --- lookup ops: no wire, accumulate histogram; never a column ---
            case WT::U16RangeCheck: {
                uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                atomicAdd(&range_hist[v + (1u << 16)], 1u);
                continue;
            }
            case WT::BitRangeCheck: {
                uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                continue;
            }
            case WT::BitRangeCheckVar: {
                uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                uint32_t bits = (uint32_t)NATS(op.b);
                if (bits <= 16)
                    atomicAdd(&range_hist[v + (1u << bits)], 1u);
                continue;
            }
            case WT::U8RangeCheck: {
                uint32_t b = (uint32_t)(uint8_t)NATS(op.a);
                uint32_t c = (uint32_t)(uint8_t)NATS(op.b);
                atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS
                                     + WITGEN_BYTE_U8RANGE_COL], 1u);
                continue;
            }
            case WT::U16RangeCheckGuarded: {
                if (NATS(op.b)) {
                    uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                    atomicAdd(&range_hist[v + (1u << 16)], 1u);
                }
                continue;
            }
            case WT::BitRangeCheckGuarded: {
                if (NATS(op.b)) {
                    uint32_t v = (uint32_t)(uint16_t)NATS(op.a);
                    atomicAdd(&range_hist[v + (1u << (uint32_t)op.imm0)], 1u);
                }
                continue;
            }
            case WT::U8RangeCheckGuarded: {
                if (NATS(op.imm1)) {
                    uint32_t b = (uint32_t)(uint8_t)NATS(op.a);
                    uint32_t c = (uint32_t)(uint8_t)NATS(op.b);
                    atomicAdd(&byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS
                                         + WITGEN_BYTE_U8RANGE_COL], 1u);
                }
                continue;
            }
            case WT::ByteLookup: {
                uint32_t b = (uint32_t)(uint8_t)NATS(op.a);
                uint32_t c = (uint32_t)(uint8_t)NATS(op.b);
                uint32_t opc = (uint32_t)NATS(op.imm1);
                if (opc < WITGEN_NUM_BYTE_MULT_COLS)
                    atomicAdd(
                        &byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                continue;
            }
            case WT::ByteLookupGuarded: {
                if (NATS((uint32_t)op.imm0)) {
                    uint32_t b = (uint32_t)(uint8_t)NATS(op.a);
                    uint32_t c = (uint32_t)(uint8_t)NATS(op.b);
                    uint32_t opc = (uint32_t)NATS(op.imm1);
                    if (opc < WITGEN_NUM_BYTE_MULT_COLS)
                        atomicAdd(
                            &byte_hist[((b << 8) + c) * WITGEN_NUM_BYTE_MULT_COLS + opc], 1u);
                }
                continue;
            }
            default:
                // Unknown/unported tag: silently skipping would shift every
                // subsequent wire (silent corruption) — abort the kernel instead.
                __trap();
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

// H2 (host-memory-workstream Phase 1): broadcast a chip's non-zero padding template
// over the PADDING rows [row_start, height) of a column-major trace. `vals` is
// [n_tmpl][period] row-major and absolute row r takes vals[j * period + r % period]
// (period 1 = constant template: sll/sr/divrem; period 80 = sha_compress's cyclic
// octet/index/k pattern). Event rows [0, row_start) are left for the witgen kernel
// to overwrite. Replaces the trace-sized host Vec fill + full-trace H2D that ran
// under the GPU permit (the F.1a-measured in-tracegen-phase seam).
template <class T>
__global__ void witgen_template_fill_kernel(
    T* __restrict__ trace,
    size_t height,
    size_t row_start,
    const uint32_t* __restrict__ cols,
    const T* __restrict__ vals,
    uint32_t period,
    uint32_t n_tmpl) {
    size_t n_rows = height - row_start;
    size_t total = (size_t)n_tmpl * n_rows;
    for (size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x; i < total;
         i += (size_t)blockDim.x * gridDim.x) {
        uint32_t j = (uint32_t)(i / n_rows);
        size_t r = row_start + (i % n_rows);
        trace[(uintptr_t)cols[j] * height + r] = vals[(size_t)j * period + (r % period)];
    }
}

namespace sp1_gpu_sys {
extern KernelPtr witgen_template_fill_koala_bear_kernel() {
    return (KernelPtr)::witgen_template_fill_kernel<kb31_t>;
}
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
