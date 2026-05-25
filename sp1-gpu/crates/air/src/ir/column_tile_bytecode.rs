//! Bytecode for the ColumnTile lowering.
//!
//! ColumnTile applies to `LinearWeightedSum` chunks: each chunk's program is
//! `Σ_k α^k · (Σ_i coeff_{k,i} · leaf_{k,i})`. We linearize that into a flat
//! list of `(leaf, coeff, alpha_idx)` term entries. The kernel runs one lane
//! per `(term, row, eval_point)` tuple, no shared cache, no per-thread tape
//! interpretation — lane variation IS the program.

use crate::ir::analysis::ConstraintInfo;
use crate::ir::bytecode::{LeafRef, LEAF_SOURCE_MAIN_LOCAL, LEAF_SOURCE_PREPROCESSED_LOCAL};
use crate::ir::chunker::Chunk;
use crate::ir::dag::{ConstraintDag, DagNode, TraceSource};
use crate::ir::lowering::ColumnTilePlan;
use crate::F;

/// Kind tag for `ColumnTermEntry.coeff_kind`. Must match the CUDA header.
pub const COEFF_KIND_CONST: u32 = 0;
pub const COEFF_KIND_PUBLIC: u32 = 1;
/// Mask isolating the kind from the negate flag (bit 31).
pub const COEFF_KIND_MASK: u32 = 0x7FFF_FFFF;
/// High bit of `coeff_kind`: when set, the kernel negates the loaded
/// coefficient before applying it. Tracks the `-` in a `SubF` spine of
/// `LinearWeightedSum` so the asserted polynomial matches the AIR.
pub const COEFF_NEGATE_BIT: u32 = 1u32 << 31;

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
                    TraceSource::PreprocessedLocal => LEAF_SOURCE_PREPROCESSED_LOCAL,
                    TraceSource::MainLocal => LEAF_SOURCE_MAIN_LOCAL,
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

        let kind_encoded = if t.negate { coeff_kind | COEFF_NEGATE_BIT } else { coeff_kind };
        bc.terms.push(ColumnTermEntry {
            leaf_idx,
            coeff_kind: kind_encoded,
            coeff_idx,
            alpha_idx: t.alpha_idx,
        });
    }

    Some(bc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::analysis::{analyze_constraints, ConstraintShape};
    use crate::ir::chunker::Chunk;
    use crate::ir::dag::{ConstraintRef, DagNode, TraceSource};
    use crate::ir::lowering::{enumerate_lowerings, Lowering};
    use slop_algebra::AbstractField;
    use std::collections::HashSet;

    /// Constraint `c0 * x0 - c1 * x1` MUST lower to ColumnTile with the
    /// second term's `COEFF_NEGATE_BIT` set. This regression-tests the
    /// `SubF` soundness fix — before it, `flatten_linear` treated `SubF`
    /// identically to `AddF`, dropping the sign on the right operand and
    /// producing a wrong asserted polynomial.
    #[test]
    fn lower_column_tile_handles_subf_sign() {
        // Build DAG:  c0 = const(7), x0 = MainLocal[0], t0 = c0 * x0
        //             c1 = const(11), x1 = MainLocal[1], t1 = c1 * x1
        //             root = SubF { a: t0, b: t1 }
        let mut nodes = Vec::new();
        let c0 = nodes.len() as u32;
        nodes.push(DagNode::ConstF { value: F::from_canonical_u32(7) });
        let x0 = nodes.len() as u32;
        nodes.push(DagNode::InputLeaf { source: TraceSource::MainLocal, col: 0 });
        let t0 = nodes.len() as u32;
        nodes.push(DagNode::MulF { a: c0, b: x0 });
        let c1 = nodes.len() as u32;
        nodes.push(DagNode::ConstF { value: F::from_canonical_u32(11) });
        let x1 = nodes.len() as u32;
        nodes.push(DagNode::InputLeaf { source: TraceSource::MainLocal, col: 1 });
        let t1 = nodes.len() as u32;
        nodes.push(DagNode::MulF { a: c1, b: x1 });
        let root = nodes.len() as u32;
        nodes.push(DagNode::SubF { a: t0, b: t1 });

        let dag = ConstraintDag {
            nodes,
            constraints: vec![ConstraintRef { root, alpha_index: 0 }],
            preprocessed_width: 0,
            main_width: 2,
        };
        let infos = analyze_constraints(&dag);
        assert!(matches!(infos[0].shape, ConstraintShape::LinearWeightedSum));

        // Single-constraint chunk covering the SubF.
        let mut leafset = HashSet::new();
        for &leaf in &infos[0].column_leaves {
            leafset.insert(leaf);
        }
        let chunk = Chunk {
            constraint_indices: vec![0],
            leafset,
            depth_max: infos[0].depth,
            shape: ConstraintShape::LinearWeightedSum,
        };

        let lowerings = enumerate_lowerings(&chunk, &infos, &dag);
        let plan = lowerings
            .iter()
            .find_map(|l| match l {
                Lowering::ColumnTile(p) => Some(p),
                _ => None,
            })
            .expect("ColumnTile lowering should apply to LinearWeightedSum chunk");
        let bc = lower_column_tile(&chunk, &infos, &dag, plan)
            .expect("ColumnTile bytecode should lower successfully");

        assert_eq!(bc.terms.len(), 2, "two terms expected for `c0*x0 - c1*x1`");

        // First term: `+ c0 * x0` — negate bit must be clear.
        let kind0 = bc.terms[0].coeff_kind & COEFF_KIND_MASK;
        let neg0 = (bc.terms[0].coeff_kind & COEFF_NEGATE_BIT) != 0;
        assert_eq!(kind0, COEFF_KIND_CONST);
        assert!(!neg0, "first term (additive) must not be negated");

        // Second term: `- c1 * x1` — negate bit MUST be set. Without the
        // fix this would be `false`, silently making the kernel evaluate
        // `c0*x0 + c1*x1` instead of `c0*x0 - c1*x1`.
        let kind1 = bc.terms[1].coeff_kind & COEFF_KIND_MASK;
        let neg1 = (bc.terms[1].coeff_kind & COEFF_NEGATE_BIT) != 0;
        assert_eq!(kind1, COEFF_KIND_CONST);
        assert!(neg1, "right-of-SubF term must carry the negate flag");
    }

    /// `c0*x0 - (c1*x1 - c2*x2)` exercises nested SubF: the inner
    /// subtraction flips again, so `c2*x2` ends up additive (parity is
    /// even). `c1*x1` is on the right side of the outer SubF only and
    /// stays negated.
    #[test]
    fn lower_column_tile_handles_nested_subf() {
        let mut nodes = Vec::new();
        let c0 = nodes.len() as u32;
        nodes.push(DagNode::ConstF { value: F::from_canonical_u32(2) });
        let x0 = nodes.len() as u32;
        nodes.push(DagNode::InputLeaf { source: TraceSource::MainLocal, col: 0 });
        let t0 = nodes.len() as u32;
        nodes.push(DagNode::MulF { a: c0, b: x0 });
        let c1 = nodes.len() as u32;
        nodes.push(DagNode::ConstF { value: F::from_canonical_u32(3) });
        let x1 = nodes.len() as u32;
        nodes.push(DagNode::InputLeaf { source: TraceSource::MainLocal, col: 1 });
        let t1 = nodes.len() as u32;
        nodes.push(DagNode::MulF { a: c1, b: x1 });
        let c2 = nodes.len() as u32;
        nodes.push(DagNode::ConstF { value: F::from_canonical_u32(5) });
        let x2 = nodes.len() as u32;
        nodes.push(DagNode::InputLeaf { source: TraceSource::MainLocal, col: 2 });
        let t2 = nodes.len() as u32;
        nodes.push(DagNode::MulF { a: c2, b: x2 });
        let inner = nodes.len() as u32;
        nodes.push(DagNode::SubF { a: t1, b: t2 });
        let root = nodes.len() as u32;
        nodes.push(DagNode::SubF { a: t0, b: inner });

        let dag = ConstraintDag {
            nodes,
            constraints: vec![ConstraintRef { root, alpha_index: 0 }],
            preprocessed_width: 0,
            main_width: 3,
        };
        let infos = analyze_constraints(&dag);
        assert!(matches!(infos[0].shape, ConstraintShape::LinearWeightedSum));

        let mut leafset = HashSet::new();
        for &leaf in &infos[0].column_leaves {
            leafset.insert(leaf);
        }
        let chunk = Chunk {
            constraint_indices: vec![0],
            leafset,
            depth_max: infos[0].depth,
            shape: ConstraintShape::LinearWeightedSum,
        };

        let lowerings = enumerate_lowerings(&chunk, &infos, &dag);
        let plan = lowerings
            .iter()
            .find_map(|l| match l {
                Lowering::ColumnTile(p) => Some(p),
                _ => None,
            })
            .expect("ColumnTile lowering should apply");
        let bc = lower_column_tile(&chunk, &infos, &dag, plan)
            .expect("ColumnTile bytecode should lower successfully");

        // Three terms — sign parities: t0 = +, t1 = - (right of outer SubF),
        // t2 = + (right of outer ⊕ right of inner = parity even).
        assert_eq!(bc.terms.len(), 3);
        let neg = |i: usize| (bc.terms[i].coeff_kind & COEFF_NEGATE_BIT) != 0;
        assert!(!neg(0), "t0 = +c0*x0");
        assert!(neg(1), "t1 = -c1*x1");
        assert!(!neg(2), "t2 = -(-c2*x2) = +c2*x2");
    }
}
