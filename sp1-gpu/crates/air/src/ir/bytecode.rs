//! Bytecode that the Sequential kernel interprets per chunk.
//!
//! Each `ChunkBytecode` is the lowered form of one `Chunk`+`SequentialPlan`:
//! - `leaves`  : per-leaf trace reference (which column, which source).
//!   Kernel loads `(zero, one)` pairs into shared memory at CTA preamble.
//! - `consts`  : pool of base-field constants. Indexed by `OpLoadConstF` instrs.
//! - `publics` : indices into the global public-values buffer.
//! - `instrs`  : flat bytecode in topological order. Each instr writes
//!   to `out`; reads from `a` / `b` are either reg slots,
//!   leaf-cache indices, or pool indices depending on opcode.
//! - `max_reg` : size of the per-lane register file (max-live count).
//! - `roots`   : the assertion roots, paired with their alpha index. The
//!   kernel reads each root reg, multiplies by `α^k`, and adds
//!   to the accumulator.
//!
//! Uses explicit leaf/const/public pools per chunk (rather than per-chip
//! globals), enabling shared-memory staging.

use crate::ir::analysis::ConstraintInfo;
use crate::ir::chunker::Chunk;
use crate::ir::dag::{ConstraintDag, DagNode, NodeId, TraceSource};
use crate::ir::lowering::SequentialPlan;
use crate::F;
use std::collections::HashMap;

/// Bytecode opcodes for the per-row register-machine the fused sequential
/// kernel interprets. Must mirror the constants in `sequential.cuh`.
/// Asserts are *not* an opcode — they live in the chunk's separate
/// `asserts: Vec<(reg, alpha_idx)>` table so the interpreter can iterate
/// them after the main bytecode body, summing `α[αᵢ] · regs[root]` into
/// the accumulator.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BcOp {
    /// out = lerp(leaf_cache[a].zero, leaf_cache[a].one, eval_pt[lane])
    LoadLeaf = 0,
    /// out = const_pool[a]
    LoadConst = 1,
    /// out = public_values[a]
    LoadPublic = 2,
    /// out = regs[a] + regs[b]
    AddF = 3,
    /// out = regs[a] - regs[b]
    SubF = 4,
    /// out = regs[a] * regs[b]
    MulF = 5,
    /// out = -regs[a]
    NegF = 6,
}

/// One bytecode instruction. 8 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DagInstr {
    pub opcode: u8,
    pub _pad: u8,
    pub out: u16,
    pub a: u16,
    pub b: u16,
}

impl DagInstr {
    pub fn new(op: BcOp, out: u16, a: u16, b: u16) -> Self {
        Self { opcode: op as u8, _pad: 0, out, a, b }
    }
}

/// Source tag for `LeafRef.source`. The encoding mirrors the jagged-mle
/// column-variant tags (3 = PreprocessedNext, 5 = MainNext) but only the
/// local-row variants are reachable from constraint lowering. Kernels
/// branch on `source == LEAF_SOURCE_MAIN_LOCAL` to pick between the chip's
/// `main_ptr` / `preprocessed_ptr` — every per-chip CUDA kernel must use
/// the same constants (mirrored in `include/zerocheck/sequential.cuh`).
pub const LEAF_SOURCE_PREPROCESSED_LOCAL: u8 = 2;
pub const LEAF_SOURCE_MAIN_LOCAL: u8 = 4;

/// Trace reference for a leaf. The kernel uses this at CTA preamble to load
/// `(zero, one)` pairs into shared memory.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeafRef {
    /// `LEAF_SOURCE_PREPROCESSED_LOCAL` or `LEAF_SOURCE_MAIN_LOCAL`. See
    /// the constants above for the encoding rationale.
    pub source: u8,
    pub _pad: u8,
    /// Column index within the chip's preprocessed or main trace.
    pub col: u32,
}

/// Lowered, ready-to-launch chunk.
#[derive(Debug, Default, Clone)]
pub struct ChunkBytecode {
    pub leaves: Vec<LeafRef>,
    pub consts: Vec<F>,
    pub publics: Vec<u32>,
    pub instrs: Vec<DagInstr>,
    /// (reg, alpha_index) per assertion in this chunk. The kernel applies
    /// `accumulator += alpha^k * regs[reg]` at the end. Kept separate
    /// from `instrs` so the schedule can drive the alpha-table read.
    pub asserts: Vec<(u16, u32)>,
    pub max_reg: u16,
    pub n_constraints: u32,
    /// If non-zero, the kernel appends a per-row GKR sweep after the bytecode
    /// and asserts pass — accumulating `Σ_i gkr_powers[i] · col_i(row)` over
    /// `gkr_main_width` main cols and `gkr_prep_width` prep cols. This fuses
    /// what would otherwise be a separate ColumnTile launch into the Sequential
    /// pass, sharing column loads with the constraint bytecode in L1.
    pub gkr_main_width: u32,
    pub gkr_prep_width: u32,
}

/// Lower a `SequentialPlan` (topological order over the chunk's DAG subgraph)
/// to flat bytecode.
///
/// Performs liveness-based register allocation: each physical register slot
/// is reused once its current occupant's last use has passed. The resulting
/// `max_reg` is the chunk's peak live count, not its node count — typically
/// a small constant for shallow constraints.
pub fn lower_sequential(
    chunk: &Chunk,
    constraints: &[ConstraintInfo],
    dag: &ConstraintDag,
    plan: &SequentialPlan,
) -> ChunkBytecode {
    let mut bc = ChunkBytecode {
        n_constraints: chunk.constraint_indices.len() as u32,
        ..ChunkBytecode::default()
    };

    let phys_of = liveness_allocate(chunk, constraints, dag, plan);

    let mut leaf_of: HashMap<(u8, u32), u16> = HashMap::new();
    let mut const_of: HashMap<u32, u16> = HashMap::new();
    let mut public_of: HashMap<u32, u16> = HashMap::new();

    // Helper: produces the operand register for a node that's already been
    // emitted (must be in `phys_of`).
    let reg = |n: NodeId| -> u16 { *phys_of.get(&n).expect("topo order broken") };

    for &node_id in &plan.topo_order {
        let node = &dag.nodes[node_id as usize];
        match *node {
            DagNode::InputLeaf { source, col } => {
                let src_byte = match source {
                    TraceSource::PreprocessedLocal => LEAF_SOURCE_PREPROCESSED_LOCAL,
                    TraceSource::MainLocal => LEAF_SOURCE_MAIN_LOCAL,
                };
                let leaf_idx = *leaf_of.entry((src_byte, col)).or_insert_with(|| {
                    let i = bc.leaves.len() as u16;
                    bc.leaves.push(LeafRef { source: src_byte, _pad: 0, col });
                    i
                });
                bc.instrs.push(DagInstr::new(BcOp::LoadLeaf, reg(node_id), leaf_idx, 0));
            }
            DagNode::ConstF { value } => {
                use slop_algebra::PrimeField32;
                let key = value.as_canonical_u32();
                let cidx = *const_of.entry(key).or_insert_with(|| {
                    let i = bc.consts.len() as u16;
                    bc.consts.push(value);
                    i
                });
                bc.instrs.push(DagInstr::new(BcOp::LoadConst, reg(node_id), cidx, 0));
            }
            DagNode::PublicValue { idx } => {
                let pidx = *public_of.entry(idx).or_insert_with(|| {
                    let i = bc.publics.len() as u16;
                    bc.publics.push(idx);
                    i
                });
                bc.instrs.push(DagInstr::new(BcOp::LoadPublic, reg(node_id), pidx, 0));
            }
            DagNode::AddF { a, b } => {
                bc.instrs.push(DagInstr::new(BcOp::AddF, reg(node_id), reg(a), reg(b)));
            }
            DagNode::SubF { a, b } => {
                bc.instrs.push(DagInstr::new(BcOp::SubF, reg(node_id), reg(a), reg(b)));
            }
            DagNode::MulF { a, b } => {
                bc.instrs.push(DagInstr::new(BcOp::MulF, reg(node_id), reg(a), reg(b)));
            }
            DagNode::NegF { a } => {
                bc.instrs.push(DagInstr::new(BcOp::NegF, reg(node_id), reg(a), 0));
            }
            // EF / mixed / cumsum / boundary singletons aren't reachable
            // from any asserted base-field root in the current chip set —
            // `DagBuilder` rejects `assert_zero_ext` so EF nodes never
            // become roots, and the other variants have no overload
            // creating them via base-field arithmetic. Trip loudly if a
            // future chip changes that invariant.
            _ => {
                panic!(
                    "Sequential kernel cannot lower node kind {:?} (node id {}); \
                     a base-field asserted root reached a non-base-field DAG node \
                     for the first time",
                    node, node_id
                );
            }
        }
    }

    // Append per-constraint assertions.
    for &ci in &chunk.constraint_indices {
        let info = &constraints[ci];
        bc.asserts.push((reg(info.root), info.alpha_index));
    }

    // `max_reg` = peak physical-reg index used + 1.
    bc.max_reg = phys_of.values().copied().max().map(|m| m + 1).unwrap_or(0);
    bc
}

/// Compute a `NodeId -> physical-register-slot` mapping by linear-scan over
/// the topological order, reusing slots whose previous occupant's last use
/// has passed.
///
/// Constraint roots are kept live to the very end so the post-topo assert
/// pass can still read them.
fn liveness_allocate(
    chunk: &Chunk,
    constraints: &[ConstraintInfo],
    dag: &ConstraintDag,
    plan: &SequentialPlan,
) -> HashMap<NodeId, u16> {
    let topo = &plan.topo_order;
    let pos_of: HashMap<NodeId, usize> = topo.iter().enumerate().map(|(i, &n)| (n, i)).collect();

    // Last-use position per node. Self-use (at the def site) counts as i.
    let mut last_use: HashMap<NodeId, usize> = HashMap::new();
    for (i, &node_id) in topo.iter().enumerate() {
        last_use.insert(node_id, i);
    }
    for (i, &node_id) in topo.iter().enumerate() {
        let node = &dag.nodes[node_id as usize];
        for child in node_children(node).into_iter().flatten() {
            if pos_of.contains_key(&child) {
                let e = last_use.entry(child).or_insert(0);
                if i > *e {
                    *e = i;
                }
            }
        }
    }
    // Constraint roots must remain live through the assert pass.
    let end = topo.len();
    for &ci in &chunk.constraint_indices {
        let root = constraints[ci].root;
        if pos_of.contains_key(&root) {
            last_use.insert(root, end);
        }
    }

    // Linear-scan: at each position, free regs whose occupants died before
    // this position; allocate from pool (else bump).
    let mut active: Vec<(u16, NodeId)> = Vec::new(); // (phys, node)
    let mut free_pool: Vec<u16> = Vec::new();
    let mut next_phys: u16 = 0;
    let mut phys_of: HashMap<NodeId, u16> = HashMap::new();

    for (i, &node_id) in topo.iter().enumerate() {
        // Free dead regs.
        active.retain(|&(p, n)| {
            if last_use[&n] < i {
                free_pool.push(p);
                false
            } else {
                true
            }
        });

        // Allocate.
        let phys = free_pool.pop().unwrap_or_else(|| {
            let p = next_phys;
            next_phys += 1;
            p
        });
        active.push((phys, node_id));
        phys_of.insert(node_id, phys);
    }

    phys_of
}

/// DAG-node child enumeration (returns the operand `NodeId`s).
fn node_children(node: &DagNode) -> [Option<NodeId>; 2] {
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
