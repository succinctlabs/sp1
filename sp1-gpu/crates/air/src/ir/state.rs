//! Global DAG-builder state, mirroring the existing `CUDA_P3_EVAL_*` pattern.
//!
//! The state is process-global, serialized by a guard lock so chip eval can
//! be done one-at-a-time. The high-level entry (`build_dag`) acquires the lock,
//! resets state, runs `chip.eval`, snapshots the result, and releases.
//!
//! This is intentionally the same shape as the v1 globals — easier to reason
//! about, easier to migrate. Can be replaced by builder-owned state once the
//! v1 path is deleted.

use std::collections::HashMap;
use std::sync::Mutex;

use lazy_static::lazy_static;

use crate::ir::dag::{ConstraintRef, DagNode, NodeId, TraceSource};
use crate::{EF, F};

/// State accumulated during a single chip's `eval`.
#[derive(Default)]
pub struct DagState {
    pub nodes: Vec<DagNode>,
    pub constraints: Vec<ConstraintRef>,

    // Interning tables for leaves and constants only.
    pub leaf_intern: HashMap<(TraceSource, u32), NodeId>,
    pub public_intern: HashMap<u32, NodeId>,
    pub gcs_intern: HashMap<u32, NodeId>,
    pub const_f_intern: HashMap<u32, NodeId>, // keyed by F's u32 repr
    pub const_ef_intern: HashMap<[u32; 4], NodeId>,
    pub singleton_is_first_row: Option<NodeId>,
    pub singleton_is_last_row: Option<NodeId>,
    pub singleton_is_transition: Option<NodeId>,

    pub num_constraints: u32,
}

impl DagState {
    pub fn alloc(&mut self, node: DagNode) -> NodeId {
        let id = self.nodes.len() as u32;
        self.nodes.push(node);
        id
    }

    pub fn intern_leaf(&mut self, source: TraceSource, col: u32) -> NodeId {
        if let Some(&id) = self.leaf_intern.get(&(source, col)) {
            return id;
        }
        let id = self.alloc(DagNode::InputLeaf { source, col });
        self.leaf_intern.insert((source, col), id);
        id
    }

    pub fn intern_public(&mut self, idx: u32) -> NodeId {
        if let Some(&id) = self.public_intern.get(&idx) {
            return id;
        }
        let id = self.alloc(DagNode::PublicValue { idx });
        self.public_intern.insert(idx, id);
        id
    }

    pub fn intern_gcs(&mut self, idx: u32) -> NodeId {
        if let Some(&id) = self.gcs_intern.get(&idx) {
            return id;
        }
        let id = self.alloc(DagNode::GlobalCumulativeSum { idx });
        self.gcs_intern.insert(idx, id);
        id
    }

    pub fn intern_const_f(&mut self, value: F) -> NodeId {
        let key = f_key(value);
        if let Some(&id) = self.const_f_intern.get(&key) {
            return id;
        }
        let id = self.alloc(DagNode::ConstF { value });
        self.const_f_intern.insert(key, id);
        id
    }

    pub fn intern_const_ef(&mut self, value: EF) -> NodeId {
        let key = ef_key(value);
        if let Some(&id) = self.const_ef_intern.get(&key) {
            return id;
        }
        let id = self.alloc(DagNode::ConstEF { value });
        self.const_ef_intern.insert(key, id);
        id
    }

    pub fn intern_is_first_row(&mut self) -> NodeId {
        if let Some(id) = self.singleton_is_first_row {
            return id;
        }
        let id = self.alloc(DagNode::IsFirstRow);
        self.singleton_is_first_row = Some(id);
        id
    }

    pub fn intern_is_last_row(&mut self) -> NodeId {
        if let Some(id) = self.singleton_is_last_row {
            return id;
        }
        let id = self.alloc(DagNode::IsLastRow);
        self.singleton_is_last_row = Some(id);
        id
    }

    pub fn intern_is_transition(&mut self) -> NodeId {
        if let Some(id) = self.singleton_is_transition {
            return id;
        }
        let id = self.alloc(DagNode::IsTransition);
        self.singleton_is_transition = Some(id);
        id
    }

    pub fn reset(&mut self) {
        self.nodes.clear();
        self.constraints.clear();
        self.leaf_intern.clear();
        self.public_intern.clear();
        self.gcs_intern.clear();
        self.const_f_intern.clear();
        self.const_ef_intern.clear();
        self.singleton_is_first_row = None;
        self.singleton_is_last_row = None;
        self.singleton_is_transition = None;
        self.num_constraints = 0;
    }
}

/// Stable key for an `F` value. Uses the canonical `u32` representation.
fn f_key(value: F) -> u32 {
    use slop_algebra::PrimeField32;
    value.as_canonical_u32()
}

/// Stable key for an `EF` value. Each base coefficient mapped via `f_key`.
fn ef_key(value: EF) -> [u32; 4] {
    use slop_algebra::AbstractExtensionField;
    let slice: &[F] = value.as_base_slice();
    assert!(slice.len() == 4, "EF degree expected to be 4");
    [f_key(slice[0]), f_key(slice[1]), f_key(slice[2]), f_key(slice[3])]
}

lazy_static! {
    /// Outer guard. Acquired by `build_dag` for the duration of one chip's eval.
    pub static ref DAG_BUILDER_LOCK: Mutex<()> = Mutex::new(());

    /// The accumulating DAG state. Mutated by operator overloads and assert_zero.
    pub static ref DAG_STATE: Mutex<DagState> = Mutex::new(DagState::default());
}

/// Convenience: lock the state and run a closure with `&mut DagState`.
pub(crate) fn with_state<R>(f: impl FnOnce(&mut DagState) -> R) -> R {
    let mut guard = DAG_STATE.lock().unwrap();
    f(&mut guard)
}
