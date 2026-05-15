//! Per-constraint DAG analysis.
//!
//! For each `ConstraintRef`, walks back from the root to compute:
//! - the transitive column-leaf set (used by the chunker)
//! - work (count of arithmetic ops; leaves and constants are free)
//! - depth (longest dependency chain to a leaf)
//! - a structural shape tag (e.g. `LinearWeightedSum` for GKR-eligible chunks)
//!
//! Output is purely derived from the `ConstraintDag` — no mutation.

use std::collections::{HashMap, HashSet};

use crate::v2::dag::{ConstraintDag, ConstraintField, DagNode, NodeId, TraceSource};

/// Identifies a column-ref leaf for chunker bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ColumnLeaf {
    pub source: TraceSource,
    pub col: u32,
}

/// Structural tag derived from the DAG shape. Used by the scheduler to pick
/// non-default lowerings (e.g. column-tile for GKR-shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintShape {
    /// `Σ_i (coeff_i · leaf_i)` form. Each leaf appears in exactly one
    /// multiplication-by-coefficient before being summed into the root.
    /// This is the shape of GKR corrections and any linear combination.
    LinearWeightedSum,
    /// Anything else.
    General,
}

#[derive(Debug, Clone)]
pub struct ConstraintInfo {
    /// Index into `dag.constraints`.
    pub constraint_idx: usize,
    pub root: NodeId,
    pub field: ConstraintField,
    pub alpha_index: u32,

    /// Total nodes in the transitive closure (leaves + consts + arithmetic).
    pub total_nodes: u32,
    /// Arithmetic op count only (excludes leaves and constants).
    pub work: u32,
    /// Longest dependency chain from root to a leaf.
    pub depth: u32,
    /// Distinct column-ref leaves reachable from root.
    pub column_leaves: HashSet<ColumnLeaf>,
    pub shape: ConstraintShape,
}

impl ConstraintInfo {
    pub fn leafset_size(&self) -> u32 {
        self.column_leaves.len() as u32
    }
}

/// Analyze all constraints in a DAG.
pub fn analyze_constraints(dag: &ConstraintDag) -> Vec<ConstraintInfo> {
    dag.constraints
        .iter()
        .enumerate()
        .map(|(i, c)| analyze_one(dag, i, c.root, c.field, c.alpha_index))
        .collect()
}

fn analyze_one(
    dag: &ConstraintDag,
    constraint_idx: usize,
    root: NodeId,
    field: ConstraintField,
    alpha_index: u32,
) -> ConstraintInfo {
    let mut depth_of: HashMap<NodeId, u32> = HashMap::new();
    let mut column_leaves: HashSet<ColumnLeaf> = HashSet::new();
    let mut work: u32 = 0;
    let mut total: u32 = 0;

    let depth = walk(dag, root, &mut depth_of, &mut column_leaves, &mut work, &mut total);
    let shape = detect_shape(dag, root, &column_leaves);

    ConstraintInfo {
        constraint_idx,
        root,
        field,
        alpha_index,
        total_nodes: total,
        work,
        depth,
        column_leaves,
        shape,
    }
}

fn walk(
    dag: &ConstraintDag,
    reg: NodeId,
    depth_of: &mut HashMap<NodeId, u32>,
    column_leaves: &mut HashSet<ColumnLeaf>,
    work: &mut u32,
    total: &mut u32,
) -> u32 {
    if let Some(&d) = depth_of.get(&reg) {
        return d;
    }
    let node = &dag.nodes[reg as usize];
    *total += 1;
    let d = match *node {
        DagNode::InputLeaf { source, col } => {
            if matches!(
                source,
                TraceSource::MainLocal
                    | TraceSource::MainNext
                    | TraceSource::PreprocessedLocal
                    | TraceSource::PreprocessedNext
            ) {
                column_leaves.insert(ColumnLeaf { source, col });
            }
            0
        }
        DagNode::ConstF { .. }
        | DagNode::ConstEF { .. }
        | DagNode::PublicValue { .. }
        | DagNode::GlobalCumulativeSum { .. }
        | DagNode::IsFirstRow
        | DagNode::IsLastRow
        | DagNode::IsTransition => 0,
        DagNode::AddF { a, b }
        | DagNode::SubF { a, b }
        | DagNode::MulF { a, b }
        | DagNode::AddEF { a, b }
        | DagNode::SubEF { a, b }
        | DagNode::MulEF { a, b }
        | DagNode::EFAddF { a, b }
        | DagNode::EFSubF { a, b }
        | DagNode::EFMulF { a, b } => {
            *work += 1;
            let da = walk(dag, a, depth_of, column_leaves, work, total);
            let db = walk(dag, b, depth_of, column_leaves, work, total);
            1 + da.max(db)
        }
        DagNode::NegF { a } | DagNode::NegEF { a } | DagNode::EFFromF { a } => {
            *work += 1;
            let da = walk(dag, a, depth_of, column_leaves, work, total);
            1 + da
        }
    };
    depth_of.insert(reg, d);
    d
}

/// Detect `Σ_i (coeff_i · leaf_i)` shape.
///
/// Walks the root's spine looking for: a chain of `Add` nodes whose leaves
/// are `Mul(const_or_public, leaf)`, terminating in a similar `Mul` or a
/// bare leaf. If the structure matches and every column leaf in the
/// constraint appears in exactly one such product, the constraint is
/// `LinearWeightedSum`.
///
/// This is the structural test for "GKR-shape" — the column-tile lowering
/// applies when this returns true.
fn detect_shape(
    dag: &ConstraintDag,
    root: NodeId,
    column_leaves: &HashSet<ColumnLeaf>,
) -> ConstraintShape {
    if column_leaves.is_empty() {
        return ConstraintShape::General;
    }
    let mut leaves_seen: HashSet<ColumnLeaf> = HashSet::new();
    if !walk_linear_sum(dag, root, &mut leaves_seen) {
        return ConstraintShape::General;
    }
    if leaves_seen == *column_leaves {
        ConstraintShape::LinearWeightedSum
    } else {
        ConstraintShape::General
    }
}

/// Recurses into an Add-chain; each leaf of the chain must be a product
/// of a coefficient (constant / public) and a single column leaf.
fn walk_linear_sum(
    dag: &ConstraintDag,
    node_id: NodeId,
    leaves_seen: &mut HashSet<ColumnLeaf>,
) -> bool {
    match dag.nodes[node_id as usize] {
        DagNode::AddF { a, b } | DagNode::SubF { a, b } => {
            walk_linear_sum(dag, a, leaves_seen) && walk_linear_sum(dag, b, leaves_seen)
        }
        DagNode::MulF { a, b } => match (coefficient(dag, a), coefficient(dag, b)) {
            (Some(_), None) => {
                extract_column_leaf(dag, b).map(|c| leaves_seen.insert(c)).unwrap_or(false)
            }
            (None, Some(_)) => {
                extract_column_leaf(dag, a).map(|c| leaves_seen.insert(c)).unwrap_or(false)
            }
            _ => false,
        },
        DagNode::InputLeaf { source, col }
            if matches!(
                source,
                TraceSource::MainLocal
                    | TraceSource::MainNext
                    | TraceSource::PreprocessedLocal
                    | TraceSource::PreprocessedNext
            ) =>
        {
            leaves_seen.insert(ColumnLeaf { source, col })
        }
        _ => false,
    }
}

/// True iff `node_id` references a constant / public / cumsum (i.e. not a
/// column read and not an arithmetic op).
fn coefficient(dag: &ConstraintDag, node_id: NodeId) -> Option<()> {
    match dag.nodes[node_id as usize] {
        DagNode::ConstF { .. }
        | DagNode::ConstEF { .. }
        | DagNode::PublicValue { .. }
        | DagNode::GlobalCumulativeSum { .. }
        | DagNode::IsFirstRow
        | DagNode::IsLastRow
        | DagNode::IsTransition => Some(()),
        _ => None,
    }
}

fn extract_column_leaf(dag: &ConstraintDag, node_id: NodeId) -> Option<ColumnLeaf> {
    match dag.nodes[node_id as usize] {
        DagNode::InputLeaf { source, col }
            if matches!(
                source,
                TraceSource::MainLocal
                    | TraceSource::MainNext
                    | TraceSource::PreprocessedLocal
                    | TraceSource::PreprocessedNext
            ) =>
        {
            Some(ColumnLeaf { source, col })
        }
        _ => None,
    }
}
