//! Var types — opaque `NodeId` wrappers used as leaves in the DAG.
//!
//! Distinct from `DagExpr*` only to satisfy `AirBuilder`'s associated-type
//! constraints; both ultimately point at DAG nodes. Operations on `DagVar*`
//! promote them to `DagExpr*` via `Into`.

use std::ops::{Add, Mul, Neg, Sub};

use crate::ir::dag::DagNode;
use crate::ir::dag::{NodeId, TraceSource};
use crate::ir::expr::{DagExprEF, DagExprF};
use crate::ir::state::with_state;
use crate::{EF, F};

/// Base-field variable. Wraps the `NodeId` of a leaf node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DagVarF(pub NodeId);

impl DagVarF {
    pub fn node_id(self) -> NodeId {
        self.0
    }

    pub fn preprocessed_local(col: u32) -> Self {
        let id = with_state(|s| s.intern_leaf(TraceSource::PreprocessedLocal, col));
        DagVarF(id)
    }

    pub fn preprocessed_next(col: u32) -> Self {
        let id = with_state(|s| s.intern_leaf(TraceSource::PreprocessedNext, col));
        DagVarF(id)
    }

    pub fn main_local(col: u32) -> Self {
        let id = with_state(|s| s.intern_leaf(TraceSource::MainLocal, col));
        DagVarF(id)
    }

    pub fn main_next(col: u32) -> Self {
        let id = with_state(|s| s.intern_leaf(TraceSource::MainNext, col));
        DagVarF(id)
    }

    pub fn public_value(idx: u32) -> Self {
        let id = with_state(|s| s.intern_public(idx));
        DagVarF(id)
    }

    pub fn global_cumulative_sum(idx: u32) -> Self {
        let id = with_state(|s| s.intern_gcs(idx));
        DagVarF(id)
    }

    pub fn is_first_row() -> Self {
        let id = with_state(|s| s.intern_is_first_row());
        DagVarF(id)
    }

    pub fn is_last_row() -> Self {
        let id = with_state(|s| s.intern_is_last_row());
        DagVarF(id)
    }

    pub fn is_transition() -> Self {
        let id = with_state(|s| s.intern_is_transition());
        DagVarF(id)
    }
}

impl From<DagVarF> for DagExprF {
    fn from(v: DagVarF) -> Self {
        DagExprF(v.0)
    }
}

// ----- Add -----
impl Add<F> for DagVarF {
    type Output = DagExprF;
    fn add(self, rhs: F) -> Self::Output {
        let a = self.0;
        let id = with_state(|s| {
            let b = s.intern_const_f(rhs);
            s.alloc(DagNode::AddF { a, b })
        });
        DagExprF(id)
    }
}

impl Add<DagVarF> for DagVarF {
    type Output = DagExprF;
    fn add(self, rhs: DagVarF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::AddF { a, b }));
        DagExprF(id)
    }
}

impl Add<DagExprF> for DagVarF {
    type Output = DagExprF;
    fn add(self, rhs: DagExprF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::AddF { a, b }));
        DagExprF(id)
    }
}

// ----- Sub -----
impl Sub<F> for DagVarF {
    type Output = DagExprF;
    fn sub(self, rhs: F) -> Self::Output {
        let a = self.0;
        let id = with_state(|s| {
            let b = s.intern_const_f(rhs);
            s.alloc(DagNode::SubF { a, b })
        });
        DagExprF(id)
    }
}

impl Sub<DagVarF> for DagVarF {
    type Output = DagExprF;
    fn sub(self, rhs: DagVarF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::SubF { a, b }));
        DagExprF(id)
    }
}

impl Sub<DagExprF> for DagVarF {
    type Output = DagExprF;
    fn sub(self, rhs: DagExprF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::SubF { a, b }));
        DagExprF(id)
    }
}

// ----- Mul -----
impl Mul<F> for DagVarF {
    type Output = DagExprF;
    fn mul(self, rhs: F) -> Self::Output {
        let a = self.0;
        let id = with_state(|s| {
            let b = s.intern_const_f(rhs);
            s.alloc(DagNode::MulF { a, b })
        });
        DagExprF(id)
    }
}

impl Mul<DagVarF> for DagVarF {
    type Output = DagExprF;
    fn mul(self, rhs: DagVarF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::MulF { a, b }));
        DagExprF(id)
    }
}

impl Mul<DagExprF> for DagVarF {
    type Output = DagExprF;
    fn mul(self, rhs: DagExprF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::MulF { a, b }));
        DagExprF(id)
    }
}

impl Neg for DagVarF {
    type Output = DagExprF;
    fn neg(self) -> Self::Output {
        let a = self.0;
        let id = with_state(|s| s.alloc(DagNode::NegF { a }));
        DagExprF(id)
    }
}

// ============================================================================
// Extension-field variant. Mirrors `SymbolicVarEF`. For now this is a thin
// wrapper that holds an EF NodeId. SP1 chips today don't use EF vars at the
// `eval` level (the existing kernel rejects nontrivial EF var variants).
// We still define the type so trait bounds are satisfied.
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DagVarEF(pub NodeId);

impl From<DagVarEF> for DagExprEF {
    fn from(v: DagVarEF) -> Self {
        DagExprEF(v.0)
    }
}

impl Mul<DagVarEF> for DagExprEF {
    type Output = DagExprEF;
    fn mul(self, rhs: DagVarEF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::MulEF { a, b }));
        DagExprEF(id)
    }
}

// Suppress unused-imports warning for EF in this file:
const _: fn() = || {
    let _: EF;
};
