//! FFI struct-layout regression tests.
//!
//! Every `#[repr(C)]` struct uploaded into a zerocheck kernel must agree
//! on size + field offsets with its C-side counterpart in
//! `sys/include/zerocheck/*.cuh`. Until this test existed the contract
//! was enforced exclusively by hand-edited "must match" comments — a
//! drift (e.g. adding a `bool` field on the Rust side without bumping
//! the C struct) silently shifted every field read and surfaced as
//! "wrong proofs in CI two weeks later."
//!
//! The CUDA side declares one `extern "C" const uint32_t*
//! zerocheck_layout_*()` probe per struct in
//! `sys/lib/zerocheck/layout_check.cu` returning a static
//! `[sizeof(T), offsetof(T, f0), offsetof(T, f1), ...]` array. Each
//! Rust test below calls its probe and asserts equality against
//! `std::mem::size_of` / `std::mem::offset_of!` for the field order
//! declared on the Rust side.
//!
//! If the test fails the next step is *not* to update the expected
//! values — it's to figure out which side drifted from the other and
//! reconcile, because the next call site of that struct is reading
//! through a shifted layout.

use sp1_gpu_air::ir::{ColumnTermEntry, DagInstr, LeafRef};
use sp1_gpu_zerocheck::prover::{BlockDispatchC, ChipLayoutC, ChunkStaticC, VirtualGeqStateC};

unsafe extern "C" {
    fn zerocheck_layout_dag_instr() -> *const u32;
    fn zerocheck_layout_leaf_ref() -> *const u32;
    fn zerocheck_layout_chunk_static() -> *const u32;
    fn zerocheck_layout_chip_layout() -> *const u32;
    fn zerocheck_layout_block_dispatch() -> *const u32;
    fn zerocheck_layout_column_term_entry() -> *const u32;
    fn zerocheck_layout_virtual_geq_state() -> *const u32;
}

/// Read `n` u32 layout values from a CUDA-side probe pointer.
unsafe fn read_layout(ptr: *const u32, n: usize) -> Vec<u32> {
    unsafe { std::slice::from_raw_parts(ptr, n).to_vec() }
}

/// Helper: compares `(size_of::<T>(), offset_of!(T, f0), ...)` against
/// the CUDA probe array. Field offsets are passed in the same order as
/// the C side `offsetof(...)` calls.
macro_rules! assert_layout {
    ($struct_name:literal, $probe:expr, $rust_size:expr, $( $field_name:literal => $rust_offset:expr ),* $(,)?) => {{
        let expected: Vec<(&'static str, u32)> = vec![
            ("sizeof", $rust_size as u32),
            $( ($field_name, $rust_offset as u32), )*
        ];
        let actual = unsafe { read_layout($probe, expected.len()) };
        for (i, (name, want)) in expected.iter().enumerate() {
            assert_eq!(
                actual[i], *want,
                "{} layout drift: field `{}` — Rust says {}, CUDA says {}",
                $struct_name, name, want, actual[i],
            );
        }
    }};
}

#[test]
fn dag_instr_layout_matches() {
    assert_layout!(
        "DagInstr",
        zerocheck_layout_dag_instr(),
        std::mem::size_of::<DagInstr>(),
        "opcode" => std::mem::offset_of!(DagInstr, opcode),
        "_pad" => std::mem::offset_of!(DagInstr, _pad),
        "out" => std::mem::offset_of!(DagInstr, out),
        "a" => std::mem::offset_of!(DagInstr, a),
        "b" => std::mem::offset_of!(DagInstr, b),
    );
}

#[test]
fn leaf_ref_layout_matches() {
    assert_layout!(
        "LeafRef",
        zerocheck_layout_leaf_ref(),
        std::mem::size_of::<LeafRef>(),
        "source" => std::mem::offset_of!(LeafRef, source),
        "_pad" => std::mem::offset_of!(LeafRef, _pad),
        "col" => std::mem::offset_of!(LeafRef, col),
    );
}

#[test]
fn chunk_static_layout_matches() {
    assert_layout!(
        "ChunkStaticC",
        zerocheck_layout_chunk_static(),
        std::mem::size_of::<ChunkStaticC>(),
        "instrs" => std::mem::offset_of!(ChunkStaticC, instrs),
        "leaves" => std::mem::offset_of!(ChunkStaticC, leaves),
        "consts" => std::mem::offset_of!(ChunkStaticC, consts),
        "publics" => std::mem::offset_of!(ChunkStaticC, publics),
        "assert_regs" => std::mem::offset_of!(ChunkStaticC, assert_regs),
        "assert_alphas" => std::mem::offset_of!(ChunkStaticC, assert_alphas),
        "n_instrs" => std::mem::offset_of!(ChunkStaticC, n_instrs),
        "n_asserts" => std::mem::offset_of!(ChunkStaticC, n_asserts),
        "chip_idx" => std::mem::offset_of!(ChunkStaticC, chip_idx),
        "gkr_main_width" => std::mem::offset_of!(ChunkStaticC, gkr_main_width),
        "gkr_prep_width" => std::mem::offset_of!(ChunkStaticC, gkr_prep_width),
        "chip_alpha_offset" => std::mem::offset_of!(ChunkStaticC, chip_alpha_offset),
    );
}

#[test]
fn chip_layout_matches() {
    assert_layout!(
        "ChipLayoutC",
        zerocheck_layout_chip_layout(),
        std::mem::size_of::<ChipLayoutC>(),
        "main_ptr" => std::mem::offset_of!(ChipLayoutC, main_ptr),
        "preprocessed_ptr" => std::mem::offset_of!(ChipLayoutC, preprocessed_ptr),
        "height" => std::mem::offset_of!(ChipLayoutC, height),
        "_pad" => std::mem::offset_of!(ChipLayoutC, _pad),
    );
}

#[test]
fn block_dispatch_layout_matches() {
    assert_layout!(
        "BlockDispatchC",
        zerocheck_layout_block_dispatch(),
        std::mem::size_of::<BlockDispatchC>(),
        "chunk_id" => std::mem::offset_of!(BlockDispatchC, chunk_id),
        "row_offset" => std::mem::offset_of!(BlockDispatchC, row_offset),
        "n_rows" => std::mem::offset_of!(BlockDispatchC, n_rows),
    );
}

#[test]
fn column_term_entry_layout_matches() {
    assert_layout!(
        "ColumnTermEntry",
        zerocheck_layout_column_term_entry(),
        std::mem::size_of::<ColumnTermEntry>(),
        "leaf_idx" => std::mem::offset_of!(ColumnTermEntry, leaf_idx),
        "coeff_kind" => std::mem::offset_of!(ColumnTermEntry, coeff_kind),
        "coeff_idx" => std::mem::offset_of!(ColumnTermEntry, coeff_idx),
        "alpha_idx" => std::mem::offset_of!(ColumnTermEntry, alpha_idx),
    );
}

#[test]
fn virtual_geq_state_layout_matches() {
    assert_layout!(
        "VirtualGeqStateC",
        zerocheck_layout_virtual_geq_state(),
        std::mem::size_of::<VirtualGeqStateC>(),
        "threshold" => std::mem::offset_of!(VirtualGeqStateC, threshold),
        "num_vars" => std::mem::offset_of!(VirtualGeqStateC, num_vars),
        "geq_coefficient" => std::mem::offset_of!(VirtualGeqStateC, geq_coefficient),
        "eq_coefficient" => std::mem::offset_of!(VirtualGeqStateC, eq_coefficient),
    );
}
