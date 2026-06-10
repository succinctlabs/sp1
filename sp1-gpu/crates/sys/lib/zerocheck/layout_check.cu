// Layout-check probes for the Rust↔CUDA `#[repr(C)]` ↔ C-struct pairs
// the zerocheck kernels rely on.
//
// Every kernel here casts a Rust-side `Vec<T>`'s raw bytes to a C struct
// pointer and reads fields by offset. A drift in field count / order /
// width on either side silently shifts every read, with the bug surfacing
// as wrong proofs or out-of-bounds reads down the road. These probes
// expose the C-side `sizeof` and `offsetof` to Rust so a single
// `assert_eq` per struct catches drift at `cargo test` time.
//
// Each `extern "C"` function returns a `const uint32_t*` pointing at a
// static array of `[sizeof(T), offsetof(T, field_0), offsetof(T, field_1),
// ...]`. The Rust-side test (`crates/zerocheck/tests/ffi_layout.rs`)
// compares against `std::mem::size_of::<RustT>()` / `std::mem::offset_of!`.

#include "zerocheck/sequential.cuh"
#include "zerocheck/column_tile.cuh"
#include "zerocheck/geq_corrections.cuh"

#include <cstdint>
#include <cstddef>

extern "C" {

const uint32_t* zerocheck_layout_dag_instr() {
    static const uint32_t L[] = {
        (uint32_t)sizeof(DagInstr),
        (uint32_t)offsetof(DagInstr, opcode),
        (uint32_t)offsetof(DagInstr, _pad),
        (uint32_t)offsetof(DagInstr, out),
        (uint32_t)offsetof(DagInstr, a),
        (uint32_t)offsetof(DagInstr, b),
    };
    return L;
}

const uint32_t* zerocheck_layout_leaf_ref() {
    static const uint32_t L[] = {
        (uint32_t)sizeof(LeafRef),
        (uint32_t)offsetof(LeafRef, source),
        (uint32_t)offsetof(LeafRef, _pad),
        (uint32_t)offsetof(LeafRef, col),
    };
    return L;
}

const uint32_t* zerocheck_layout_chunk_static() {
    static const uint32_t L[] = {
        (uint32_t)sizeof(ChunkStatic),
        (uint32_t)offsetof(ChunkStatic, instrs),
        (uint32_t)offsetof(ChunkStatic, leaves),
        (uint32_t)offsetof(ChunkStatic, consts),
        (uint32_t)offsetof(ChunkStatic, publics),
        (uint32_t)offsetof(ChunkStatic, assert_regs),
        (uint32_t)offsetof(ChunkStatic, assert_alphas),
        (uint32_t)offsetof(ChunkStatic, n_instrs),
        (uint32_t)offsetof(ChunkStatic, n_asserts),
        (uint32_t)offsetof(ChunkStatic, chip_idx),
        (uint32_t)offsetof(ChunkStatic, gkr_main_width),
        (uint32_t)offsetof(ChunkStatic, gkr_prep_width),
        (uint32_t)offsetof(ChunkStatic, chip_alpha_offset),
    };
    return L;
}

const uint32_t* zerocheck_layout_chip_layout() {
    static const uint32_t L[] = {
        (uint32_t)sizeof(ChipLayout),
        (uint32_t)offsetof(ChipLayout, main_ptr),
        (uint32_t)offsetof(ChipLayout, preprocessed_ptr),
        (uint32_t)offsetof(ChipLayout, height),
        (uint32_t)offsetof(ChipLayout, _pad),
    };
    return L;
}

const uint32_t* zerocheck_layout_block_dispatch() {
    static const uint32_t L[] = {
        (uint32_t)sizeof(BlockDispatch),
        (uint32_t)offsetof(BlockDispatch, chunk_id),
        (uint32_t)offsetof(BlockDispatch, row_offset),
        (uint32_t)offsetof(BlockDispatch, n_rows),
    };
    return L;
}

const uint32_t* zerocheck_layout_column_term_entry() {
    static const uint32_t L[] = {
        (uint32_t)sizeof(ColumnTermEntry),
        (uint32_t)offsetof(ColumnTermEntry, leaf_idx),
        (uint32_t)offsetof(ColumnTermEntry, coeff_kind),
        (uint32_t)offsetof(ColumnTermEntry, coeff_idx),
        (uint32_t)offsetof(ColumnTermEntry, alpha_idx),
    };
    return L;
}

const uint32_t* zerocheck_layout_virtual_geq_state() {
    static const uint32_t L[] = {
        (uint32_t)sizeof(VirtualGeqState),
        (uint32_t)offsetof(VirtualGeqState, threshold),
        (uint32_t)offsetof(VirtualGeqState, num_vars),
        (uint32_t)offsetof(VirtualGeqState, geq_coefficient),
        (uint32_t)offsetof(VirtualGeqState, eq_coefficient),
    };
    return L;
}

}  // extern "C"
