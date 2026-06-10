//! Lowering plans per chunk.
//!
//! A `Lowering` describes one way to execute a chunk on the GPU. The IR
//! itself is lowering-agnostic — these plans are derived from a chunk plus
//! its constraint DAGs, pre-computed once per (chunk, chip-set) and reused
//! across sumcheck rounds.
//!
//! Currently ships Sequential + ColumnTile.

use crate::ir::analysis::{ConstraintInfo, ConstraintShape};
use crate::ir::chunker::Chunk;
use crate::ir::dag::{ConstraintDag, NodeId};

/// One executable plan for a chunk. The scheduler picks one of these per
/// `(chunk, round)` based on the lane budget at that round.
#[derive(Debug, Clone)]
pub enum Lowering {
    /// One thread per `(row, eval)` lane. Walks the DAG sequentially in
    /// topological order. Cache `(zero, one)` leaves in shared memory at
    /// CTA preamble; each lane evaluates the same DAG in its own register
    /// file. Work-optimal — pays nothing for parallelism beyond the lane
    /// axis.
    Sequential(SequentialPlan),

    /// Lanes vary along `(col, row, eval)`. Each lane reads one column's
    /// `(zero, one)` direct from global (no shared cache). Only applies
    /// when the chunk's DAG is `Σ_i (coeff_i · leaf_i)` over a contiguous
    /// column range.
    ColumnTile(ColumnTilePlan),
}

#[derive(Debug, Clone)]
pub struct SequentialPlan {
    /// Topologically-sorted node IDs across the chunk's constituent DAGs.
    /// `topo_order[0]` is evaluated first; `topo_order.last()` is one of
    /// the constraint roots.
    pub topo_order: Vec<NodeId>,
    /// Number of distinct DAG values live at any one point. The kernel
    /// allocates this many per-thread registers (or shared slots, per the
    /// downstream allocator).
    pub max_live: u32,
    /// Total arithmetic ops counted on the deduplicated topo order — reflects
    /// actual emission cost after CSE.
    pub topo_work: u32,
}

#[derive(Debug, Clone)]
pub struct ColumnTilePlan {
    /// Flat term list across the chunk's constituent constraints.
    pub terms: Vec<ColumnTilePlanTerm>,
}

#[derive(Debug, Clone, Copy)]
pub struct ColumnTilePlanTerm {
    /// Node ID of the coefficient (must be a constant or public).
    pub coeff_node: NodeId,
    /// Node ID of the column leaf.
    pub leaf_node: NodeId,
    /// `α^k` index for the constraint that owns this term.
    pub alpha_idx: u32,
    /// True when this term sits on the right side of an odd number of
    /// `SubF` nodes along the path to the linear-sum root. The lowering
    /// passes it through to `ColumnTermEntry`'s `COEFF_NEGATE_BIT` so the
    /// kernel flips the loaded coefficient.
    pub negate: bool,
}

/// Enumerate the lowerings that *apply* to this chunk. Always includes
/// Sequential; includes ColumnTile only if the chunk's shape allows.
///
/// Note: this returns plans, not a single choice. The scheduler picks one
/// at dispatch time given the round's lane budget.
pub fn enumerate_lowerings(
    chunk: &Chunk,
    constraints: &[ConstraintInfo],
    dag: &ConstraintDag,
) -> Vec<Lowering> {
    let mut out = Vec::new();
    out.push(Lowering::Sequential(build_sequential(chunk, constraints, dag)));
    if matches!(chunk.shape, ConstraintShape::LinearWeightedSum) {
        if let Some(plan) = build_column_tile(chunk, constraints, dag) {
            out.push(Lowering::ColumnTile(plan));
        }
    }
    out
}

/// Topological sort of the union of constraint subgraphs in the chunk.
fn build_sequential(
    chunk: &Chunk,
    constraints: &[ConstraintInfo],
    dag: &ConstraintDag,
) -> SequentialPlan {
    use std::collections::HashSet;

    let roots: Vec<NodeId> =
        chunk.constraint_indices.iter().map(|&ci| constraints[ci].root).collect();

    let mut visited: HashSet<NodeId> = HashSet::new();
    let mut topo_order: Vec<NodeId> = Vec::new();
    for &root in &roots {
        post_order(dag, root, &mut visited, &mut topo_order);
    }

    let topo_work =
        topo_order.iter().filter(|&&n| is_arithmetic(&dag.nodes[n as usize])).count() as u32;

    // Liveness-bound: walk in topo order, track which already-emitted nodes
    // still have un-emitted parents. Conservative O(N²) sweep — fine for
    // chunk sizes today.
    let max_live = compute_max_live(&topo_order, dag);

    SequentialPlan { topo_order, max_live, topo_work }
}

fn post_order(
    dag: &ConstraintDag,
    node_id: NodeId,
    visited: &mut std::collections::HashSet<NodeId>,
    out: &mut Vec<NodeId>,
) {
    if !visited.insert(node_id) {
        return;
    }
    for child in children(&dag.nodes[node_id as usize]).into_iter().flatten() {
        post_order(dag, child, visited, out);
    }
    out.push(node_id);
}

fn children(node: &crate::ir::dag::DagNode) -> [Option<NodeId>; 2] {
    use crate::ir::dag::DagNode::*;
    match *node {
        InputLeaf { .. }
        | PublicValue { .. }
        | GlobalCumulativeSum { .. }
        | ConstF { .. }
        | ConstEF { .. }
        | IsFirstRow
        | IsLastRow
        | IsTransition => [None, None],
        AddF { a, b }
        | SubF { a, b }
        | MulF { a, b }
        | AddEF { a, b }
        | SubEF { a, b }
        | MulEF { a, b }
        | EFAddF { a, b }
        | EFSubF { a, b }
        | EFMulF { a, b } => [Some(a), Some(b)],
        NegF { a } | NegEF { a } | EFFromF { a } => [Some(a), None],
    }
}

fn is_arithmetic(node: &crate::ir::dag::DagNode) -> bool {
    use crate::ir::dag::DagNode::*;
    !matches!(
        node,
        InputLeaf { .. }
            | PublicValue { .. }
            | GlobalCumulativeSum { .. }
            | ConstF { .. }
            | ConstEF { .. }
            | IsFirstRow
            | IsLastRow
            | IsTransition
    )
}

fn compute_max_live(topo: &[NodeId], dag: &ConstraintDag) -> u32 {
    // For each node, find the last position it's used. live(i) = count of
    // nodes whose first-emit ≤ i and last-use ≥ i.
    let pos_of: std::collections::HashMap<NodeId, usize> =
        topo.iter().enumerate().map(|(i, &n)| (n, i)).collect();

    let mut last_use: std::collections::HashMap<NodeId, usize> =
        topo.iter().map(|&n| (n, 0)).collect();
    for (i, &n) in topo.iter().enumerate() {
        for c in children(&dag.nodes[n as usize]).into_iter().flatten() {
            if let Some(&p) = pos_of.get(&c) {
                let _ = p; // suppress unused
                let e = last_use.entry(c).or_insert(0);
                if i > *e {
                    *e = i;
                }
            }
        }
    }

    let mut max_live: u32 = 0;
    let mut live: u32 = 0;
    let mut end_at: std::collections::HashMap<usize, Vec<NodeId>> = Default::default();
    for (i, &n) in topo.iter().enumerate() {
        live += 1;
        end_at.entry(*last_use.get(&n).unwrap_or(&i)).or_default().push(n);
        max_live = max_live.max(live);
        if let Some(ending) = end_at.get(&i) {
            live = live.saturating_sub(ending.len() as u32);
        }
    }
    max_live
}

/// Try to materialize a column-tile plan: requires every constraint in
/// the chunk to be `LinearWeightedSum`. Each constraint's terms get tagged
/// with its `alpha_index` so the kernel can weight them correctly, and
/// with a per-term `negate` flag so a `SubF` spine produces the correct
/// asserted polynomial (the right-hand side of every `Sub` contributes
/// with a flipped coefficient).
fn build_column_tile(
    chunk: &Chunk,
    constraints: &[ConstraintInfo],
    dag: &ConstraintDag,
) -> Option<ColumnTilePlan> {
    let mut terms: Vec<ColumnTilePlanTerm> = Vec::new();
    for &ci in &chunk.constraint_indices {
        let c = &constraints[ci];
        if !matches!(c.shape, ConstraintShape::LinearWeightedSum) {
            return None;
        }
        let mut raw: Vec<FlattenedTerm> = Vec::new();
        flatten_linear(dag, c.root, false, &mut raw)?;
        for FlattenedTerm { coeff, leaf, negate } in raw {
            terms.push(ColumnTilePlanTerm {
                coeff_node: coeff,
                leaf_node: leaf,
                alpha_idx: c.alpha_index,
                negate,
            });
        }
    }
    Some(ColumnTilePlan { terms })
}

/// One term extracted from a linear-sum spine: the coefficient node, the
/// column-leaf node, and a `negate` flag tracking whether the term appears
/// on the right side of an odd number of `SubF` nodes (i.e., its
/// coefficient should be flipped before evaluation).
struct FlattenedTerm {
    coeff: NodeId,
    leaf: NodeId,
    negate: bool,
}

/// Walk an Add/Sub-of-Mul tree, pushing each `(coefficient, column_leaf,
/// negate)` triple. `negate` tracks the parity of `SubF` right-children
/// along the path to each leaf so the asserted polynomial matches the
/// AIR exactly: `a - b` produces `[(coeff_a, leaf_a, false), (coeff_b,
/// leaf_b, true)]`, not `[(.., false), (.., false)]`.
fn flatten_linear(
    dag: &ConstraintDag,
    node_id: NodeId,
    negate: bool,
    out: &mut Vec<FlattenedTerm>,
) -> Option<()> {
    use crate::ir::dag::DagNode::*;
    match dag.nodes[node_id as usize] {
        AddF { a, b } => {
            flatten_linear(dag, a, negate, out)?;
            flatten_linear(dag, b, negate, out)?;
            Some(())
        }
        SubF { a, b } => {
            flatten_linear(dag, a, negate, out)?;
            flatten_linear(dag, b, !negate, out)?;
            Some(())
        }
        MulF { a, b } => {
            let a_is_coeff = is_coefficient(dag, a);
            let b_is_coeff = is_coefficient(dag, b);
            match (a_is_coeff, b_is_coeff) {
                (true, false) => {
                    out.push(FlattenedTerm { coeff: a, leaf: b, negate });
                    Some(())
                }
                (false, true) => {
                    out.push(FlattenedTerm { coeff: b, leaf: a, negate });
                    Some(())
                }
                _ => None,
            }
        }
        InputLeaf { .. } => {
            // Bare leaf at the spine — synthesize a coefficient-of-one node ID.
            // We can't allocate here; punt by skipping this case for now.
            // (Linear-sum chunks with bare-leaf terms are rare; revisit if seen.)
            None
        }
        _ => None,
    }
}

fn is_coefficient(dag: &ConstraintDag, node_id: NodeId) -> bool {
    use crate::ir::dag::DagNode::*;
    matches!(
        dag.nodes[node_id as usize],
        ConstF { .. }
            | ConstEF { .. }
            | PublicValue { .. }
            | GlobalCumulativeSum { .. }
            | IsFirstRow
            | IsLastRow
            | IsTransition
    )
}
