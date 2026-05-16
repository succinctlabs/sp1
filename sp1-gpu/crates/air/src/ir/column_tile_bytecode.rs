//! Bytecode for the ColumnTile lowering.
//!
//! ColumnTile applies to `LinearWeightedSum` chunks: each chunk's program is
//! `Σ_k α^k · (Σ_i coeff_{k,i} · leaf_{k,i})`. We linearize that into a flat
//! list of `(leaf, coeff, alpha_idx)` term entries. The kernel runs one lane
//! per `(term, row, eval_point)` tuple, no shared cache, no per-thread tape
//! interpretation — lane variation IS the program.

use crate::ir::analysis::ConstraintInfo;
use crate::ir::bytecode::LeafRef;
use crate::ir::chunker::Chunk;
use crate::ir::dag::{ConstraintDag, DagNode, TraceSource};
use crate::ir::lowering::ColumnTilePlan;
use crate::F;

/// Kind tag for `ColumnTermEntry.coeff_kind`. Must match the CUDA header.
pub const COEFF_KIND_CONST: u32 = 0;
pub const COEFF_KIND_PUBLIC: u32 = 1;
/// Coefficient is an extension-field value supplied at launch time via the
/// kernel's `runtime_coeffs` buffer. Used by GKR-correction chunks: each
/// `batching_power_i` is a per-proof random challenge, not a DAG constant.
pub const COEFF_KIND_RUNTIME: u32 = 2;

/// One term: `α^k · coeff · leaf_i(row, eval)`.
///
/// `coeff_kind` discriminates between the const pool and the public-values
/// pool. `coeff_idx` indexes into the respective table. Layout matches the
/// device-side struct in `column_tile.cuh`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ColumnTermEntry {
    pub leaf_idx: u32,
    pub coeff_kind: u32,
    pub coeff_idx: u32,
    pub alpha_idx: u32,
}

#[derive(Debug, Default, Clone)]
pub struct ColumnTileBytecode {
    pub leaves: Vec<LeafRef>,
    pub consts: Vec<F>,
    pub publics: Vec<u32>,
    pub terms: Vec<ColumnTermEntry>,
    pub n_constraints: u32,
    /// True iff this is a `synthesize_gkr_chunk` output — the GKR-sweep
    /// carrier for a chip with no Sequential chunk. Its terms are weighted
    /// by `EF::one()`, so at launch the kernel must read the `powers_of_alpha`
    /// slot holding `1` (the last slot) rather than applying the per-chip
    /// alpha shift. (A chip with 0 constraints has `chip_alpha_offset` equal
    /// to the table length, so the per-chip shift would read out of bounds.)
    pub is_gkr_carrier: bool,
}

/// Lower a `ColumnTilePlan` to flat term-entry bytecode.
///
/// Returns `None` if any coefficient is not a constant or public value —
/// the plan-detector accepts a wider set (IsFirstRow etc.) but those will
/// be handled in a future phase. Returns `None` rather than panicking so
/// the scheduler can fall back to Sequential.
pub fn lower_column_tile(
    chunk: &Chunk,
    _constraints: &[ConstraintInfo],
    dag: &ConstraintDag,
    plan: &ColumnTilePlan,
) -> Option<ColumnTileBytecode> {
    let mut bc = ColumnTileBytecode {
        n_constraints: chunk.constraint_indices.len() as u32,
        ..ColumnTileBytecode::default()
    };

    // Intern leaves, consts, publics by (source, col) / value / idx respectively.
    let mut leaf_lookup: std::collections::HashMap<(u8, u32), u32> = Default::default();
    let mut const_lookup: std::collections::HashMap<u32, u32> = Default::default();
    let mut public_lookup: std::collections::HashMap<u32, u32> = Default::default();

    for t in &plan.terms {
        // Leaf side.
        let (src_byte, col) = match dag.nodes[t.leaf_node as usize] {
            DagNode::InputLeaf { source, col } => {
                let s = match source {
                    TraceSource::PreprocessedLocal => 2u8,
                    TraceSource::PreprocessedNext => 3,
                    TraceSource::MainLocal => 4,
                    TraceSource::MainNext => 5,
                };
                (s, col)
            }
            _ => return None,
        };
        let leaf_idx = *leaf_lookup.entry((src_byte, col)).or_insert_with(|| {
            let i = bc.leaves.len() as u32;
            bc.leaves.push(LeafRef { source: src_byte, _pad: 0, col });
            i
        });

        // Coefficient side.
        let (coeff_kind, coeff_idx) = match dag.nodes[t.coeff_node as usize] {
            DagNode::ConstF { value } => {
                use slop_algebra::PrimeField32;
                let key = value.as_canonical_u32();
                let idx = *const_lookup.entry(key).or_insert_with(|| {
                    let i = bc.consts.len() as u32;
                    bc.consts.push(value);
                    i
                });
                (COEFF_KIND_CONST, idx)
            }
            DagNode::PublicValue { idx } => {
                let pidx = *public_lookup.entry(idx).or_insert_with(|| {
                    let i = bc.publics.len() as u32;
                    bc.publics.push(idx);
                    i
                });
                (COEFF_KIND_PUBLIC, pidx)
            }
            // Other coefficient kinds (IsFirstRow, EF consts, cumsum) — not yet supported.
            _ => return None,
        };

        bc.terms.push(ColumnTermEntry { leaf_idx, coeff_kind, coeff_idx, alpha_idx: t.alpha_idx });
    }

    Some(bc)
}

/// Synthesize a GKR-correction chunk for a chip.
///
/// Produces a `ColumnTileBytecode` whose program is
/// `Σ_i batching_power_i · col_i`, summed across all main and preprocessed
/// columns. Coefficient kind is `RUNTIME` — the caller supplies a per-launch
/// `runtime_coeffs: &[EF]` of length `main_width + preprocessed_width`.
///
/// Term ordering matches v1's `jaggedConstraintPolyEval` GKR loop: main
/// columns first (indices `0 .. main_width`), then preprocessed
/// (indices `main_width .. main_width + preprocessed_width`). The caller
/// must lay out `runtime_coeffs` in this order.
///
/// The GKR correction is added without an α weighting (weight `EF::one()`).
/// Terms store `alpha_idx = 0` and the chunk is flagged `is_gkr_carrier`; at
/// launch the kernel reads the `powers_of_alpha` slot holding `1` (the last
/// slot) directly, bypassing the per-chip alpha shift — which would be
/// out-of-bounds for a chip with 0 constraints.
pub fn synthesize_gkr_chunk(main_width: u32, preprocessed_width: u32) -> ColumnTileBytecode {
    let mut bc =
        ColumnTileBytecode { is_gkr_carrier: true, n_constraints: 1, ..Default::default() };

    let push_term = |bc: &mut ColumnTileBytecode, source: u8, col: u32| {
        let leaf_idx = bc.leaves.len() as u32;
        bc.leaves.push(LeafRef { source, _pad: 0, col });
        let coeff_idx = bc.terms.len() as u32;
        bc.terms.push(ColumnTermEntry {
            leaf_idx,
            coeff_kind: COEFF_KIND_RUNTIME,
            coeff_idx,
            alpha_idx: 0,
        });
    };

    // Main columns first (source byte 4 = MainLocal).
    for col in 0..main_width {
        push_term(&mut bc, 4, col);
    }
    // Then preprocessed (source byte 2 = PreprocessedLocal).
    for col in 0..preprocessed_width {
        push_term(&mut bc, 2, col);
    }

    bc
}
