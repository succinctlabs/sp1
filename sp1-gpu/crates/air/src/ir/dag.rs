//! DAG-native IR for AIR constraints.
//!
//! Each chip's eval produces a single `ConstraintDag` with explicit
//! cross-constraint sharing via shared `NodeId`s. Leaves and constants are
//! interned during construction; arithmetic nodes are not (Rust-variable
//! reuse handles the common case, full CSE deferred to a post-pass if
//! measurement justifies).

use crate::{EF, F};

/// A handle into `ConstraintDag::nodes`. Allocated monotonically by the builder.
pub type NodeId = u32;

/// Which trace a leaf comes from. Constraints in this architecture only ever
/// reference the local row, so there is no "next row" variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraceSource {
    PreprocessedLocal,
    MainLocal,
}

/// One node in the DAG.
///
/// Leaves carry their identity (column index, public-value index, constant value)
/// so the chunker can group by leaf overlap without an extra lookup. Internal
/// nodes reference their inputs by `NodeId`; sharing is whenever the same
/// `NodeId` appears as input to multiple parents.
#[derive(Debug, Clone, Copy)]
pub enum DagNode {
    // ----- Leaves (interned) -----
    InputLeaf {
        source: TraceSource,
        col: u32,
    },
    PublicValue {
        idx: u32,
    },
    GlobalCumulativeSum {
        idx: u32,
    },
    ConstF {
        value: F,
    },
    ConstEF {
        value: EF,
    },
    IsFirstRow,
    IsLastRow,
    IsTransition,

    // ----- Base-field arithmetic -----
    AddF {
        a: NodeId,
        b: NodeId,
    },
    SubF {
        a: NodeId,
        b: NodeId,
    },
    MulF {
        a: NodeId,
        b: NodeId,
    },
    NegF {
        a: NodeId,
    },

    // ----- Extension-field arithmetic -----
    AddEF {
        a: NodeId,
        b: NodeId,
    },
    SubEF {
        a: NodeId,
        b: NodeId,
    },
    MulEF {
        a: NodeId,
        b: NodeId,
    },
    NegEF {
        a: NodeId,
    },

    // ----- Mixed (EF, F) -----
    /// Lift base-field value `a` into the extension field.
    EFFromF {
        a: NodeId,
    },
    /// `a: EF + b: F`.
    EFAddF {
        a: NodeId,
        b: NodeId,
    },
    /// `a: EF - b: F`.
    EFSubF {
        a: NodeId,
        b: NodeId,
    },
    /// `a: EF * b: F`.
    EFMulF {
        a: NodeId,
        b: NodeId,
    },
}

/// One top-level assertion. Produced by `assert_zero` (all constraints are over
/// the base field; the extension-field builder hook is `unimplemented!`).
#[derive(Debug, Clone, Copy)]
pub struct ConstraintRef {
    pub root: NodeId,
    pub alpha_index: u32,
}

/// Output of running a chip's `eval` against `DagBuilder`.
#[derive(Debug)]
pub struct ConstraintDag {
    pub nodes: Vec<DagNode>,
    pub constraints: Vec<ConstraintRef>,
    pub preprocessed_width: u32,
    pub main_width: u32,
}

impl ConstraintDag {
    pub fn num_nodes(&self) -> usize {
        self.nodes.len()
    }

    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }
}
