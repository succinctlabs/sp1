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
    /// out = regs[a] * const_pool[b].
    MulConst = 7,
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

/// Lower one existing chunk, preserving its assertions and limiting scratch
/// slots to the unsimplified schedule's peak. All temporary metadata is local
/// to the chunk; the full chip DAG is neither changed nor copied.
pub fn lower_sequential(
    chunk: &Chunk,
    constraints: &[ConstraintInfo],
    dag: &ConstraintDag,
    plan: &SequentialPlan,
) -> ChunkBytecode {
    let original_max = liveness_allocate(chunk, constraints, dag, plan)
        .values()
        .copied()
        .max()
        .map_or(0, |r| r + 1);
    let local = compact_chunk(chunk, constraints, dag, plan, true);
    let bc = emit_chunk(&local);
    if bc.max_reg <= original_max {
        return bc;
    }
    // Aliasing can change lifetimes. Keep the original evaluation order if
    // the rewritten schedule ever needs more scratch on a different chip.
    let bc = emit_chunk(&compact_chunk(chunk, constraints, dag, plan, false));
    assert!(bc.max_reg <= original_max);
    bc
}

struct LocalChunk {
    nodes: Vec<DagNode>,
    roots: Vec<(NodeId, u32)>,
}

fn compact_chunk(
    chunk: &Chunk,
    constraints: &[ConstraintInfo],
    dag: &ConstraintDag,
    plan: &SequentialPlan,
    simplify: bool,
) -> LocalChunk {
    use slop_algebra::AbstractField;
    use DagNode::*;
    let mut nodes = Vec::with_capacity(plan.topo_order.len());
    let mut alias = HashMap::<NodeId, NodeId>::with_capacity(plan.topo_order.len());
    for &id in &plan.topo_order {
        let node = match dag.nodes[id as usize] {
            AddF { a, b } => AddF { a: alias[&a], b: alias[&b] },
            SubF { a, b } => SubF { a: alias[&a], b: alias[&b] },
            MulF { a, b } => MulF { a: alias[&a], b: alias[&b] },
            NegF { a } => NegF { a: alias[&a] },
            n @ (InputLeaf { .. } | ConstF { .. } | PublicValue { .. }) => n,
            n => panic!("Sequential kernel cannot lower node kind {n:?} (node id {id})"),
        };
        let is_const =
            |n: NodeId, v: F| matches!(nodes[n as usize], ConstF { value } if value == v);
        let replacement = if simplify {
            match node {
                MulF { a, .. } if is_const(a, F::zero()) => Some(a),
                MulF { b, .. } if is_const(b, F::zero()) => Some(b),
                MulF { a, b } if is_const(a, F::one()) => Some(b),
                MulF { a, b } if is_const(b, F::one()) => Some(a),
                AddF { a, b } if is_const(a, F::zero()) => Some(b),
                AddF { a, b } if is_const(b, F::zero()) => Some(a),
                SubF { a, b } if is_const(b, F::zero()) => Some(a),
                NegF { a } if is_const(a, F::zero()) => Some(a),
                _ => None,
            }
        } else {
            None
        };
        let local_id = replacement.unwrap_or_else(|| {
            let n = nodes.len() as NodeId;
            nodes.push(node);
            n
        });
        alias.insert(id, local_id);
    }
    let roots = chunk
        .constraint_indices
        .iter()
        .map(|&ci| {
            let info = &constraints[ci];
            (alias[&info.root], info.alpha_index)
        })
        .collect();
    LocalChunk { nodes, roots }
}

#[derive(Clone, Copy)]
enum MulKind {
    General(NodeId, NodeId),
    Constant(NodeId, F),
}

fn multiplication(nodes: &[DagNode], a: NodeId, b: NodeId) -> MulKind {
    for (x, c) in [(a, b), (b, a)] {
        if let DagNode::ConstF { value } = nodes[c as usize] {
            return MulKind::Constant(x, value);
        }
    }
    MulKind::General(a, b)
}

fn execution_children(nodes: &[DagNode], id: NodeId) -> [Option<NodeId>; 2] {
    if let DagNode::MulF { a, b } = nodes[id as usize] {
        match multiplication(nodes, a, b) {
            MulKind::Constant(x, _) => [Some(x), None],
            MulKind::General(a, b) => [Some(a), Some(b)],
        }
    } else {
        node_children(&nodes[id as usize])
    }
}

fn emit_chunk(local: &LocalChunk) -> ChunkBytecode {
    // Prune after aliasing and operand fusion. Retain even constant-zero roots:
    // every original assertion and alpha index is emitted below.
    let nodes = &local.nodes;
    let mut live = vec![false; nodes.len()];
    let mut pending: Vec<_> = local.roots.iter().map(|&(n, _)| n).collect();
    while let Some(n) = pending.pop() {
        if std::mem::replace(&mut live[n as usize], true) {
            continue;
        }
        pending.extend(execution_children(nodes, n).into_iter().flatten());
    }
    let topo: Vec<_> = (0..nodes.len()).filter(|&n| live[n]).collect();
    let mut last = vec![0; nodes.len()];
    for (i, &n) in topo.iter().enumerate() {
        last[n] = last[n].max(i);
        for c in execution_children(nodes, n as NodeId).into_iter().flatten() {
            last[c as usize] = last[c as usize].max(i);
        }
    }
    for &(n, _) in &local.roots {
        last[n as usize] = topo.len();
    }
    let mut phys = vec![0u16; nodes.len()];
    let mut active = Vec::<(usize, u16)>::new();
    let mut free = Vec::new();
    let mut max_reg = 0u16;
    for (i, &n) in topo.iter().enumerate() {
        active.retain(|&(old, r)| {
            if last[old] < i {
                free.push(r);
                false
            } else {
                true
            }
        });
        let r = free.pop().unwrap_or_else(|| {
            let r = max_reg;
            max_reg = max_reg.checked_add(1).expect("too many bytecode registers");
            r
        });
        phys[n] = r;
        active.push((n, r));
    }
    let reg = |n: NodeId| phys[n as usize];
    let mut bc = ChunkBytecode {
        max_reg,
        n_constraints: local.roots.len() as u32,
        ..ChunkBytecode::default()
    };
    let mut leaf_of = HashMap::new();
    let mut const_of = HashMap::new();
    let mut public_of = HashMap::new();
    for n in topo {
        let out = phys[n];
        use DagNode::*;
        let instr = match nodes[n] {
            InputLeaf { source, col } => {
                let source = match source {
                    TraceSource::MainLocal => LEAF_SOURCE_MAIN_LOCAL,
                    TraceSource::PreprocessedLocal => LEAF_SOURCE_PREPROCESSED_LOCAL,
                };
                let idx = *leaf_of.entry((source, col)).or_insert_with(|| {
                    let idx = bc.leaves.len() as u16;
                    bc.leaves.push(LeafRef { source, _pad: 0, col });
                    idx
                });
                DagInstr::new(BcOp::LoadLeaf, out, idx, 0)
            }
            ConstF { value } => {
                let idx = const_index(value, &mut bc.consts, &mut const_of);
                DagInstr::new(BcOp::LoadConst, out, idx, 0)
            }
            PublicValue { idx } => {
                let pidx = *public_of.entry(idx).or_insert_with(|| {
                    let pidx = bc.publics.len() as u16;
                    bc.publics.push(idx);
                    pidx
                });
                DagInstr::new(BcOp::LoadPublic, out, pidx, 0)
            }
            AddF { a, b } => DagInstr::new(BcOp::AddF, out, reg(a), reg(b)),
            SubF { a, b } => DagInstr::new(BcOp::SubF, out, reg(a), reg(b)),
            NegF { a } => DagInstr::new(BcOp::NegF, out, reg(a), 0),
            MulF { a, b } => match multiplication(nodes, a, b) {
                MulKind::General(a, b) => DagInstr::new(BcOp::MulF, out, reg(a), reg(b)),
                MulKind::Constant(a, value) => {
                    let idx = const_index(value, &mut bc.consts, &mut const_of);
                    DagInstr::new(BcOp::MulConst, out, reg(a), idx)
                }
            },
            _ => unreachable!("compact_chunk rejects unsupported nodes"),
        };
        bc.instrs.push(instr);
    }
    bc.asserts = local.roots.iter().map(|&(n, alpha)| (reg(n), alpha)).collect();
    bc
}

fn const_index(value: F, pool: &mut Vec<F>, indices: &mut HashMap<u32, u16>) -> u16 {
    use slop_algebra::PrimeField32;
    *indices.entry(value.as_canonical_u32()).or_insert_with(|| {
        let idx = pool.len() as u16;
        pool.push(value);
        idx
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        analyze_constraints, enumerate_lowerings, ConstraintRef, ConstraintShape, Lowering,
    };
    use slop_algebra::AbstractField;

    #[test]
    fn identities_preserve_assertions_and_scratch_bound() {
        use DagNode::*;
        let dag = ConstraintDag {
            nodes: vec![
                InputLeaf { source: TraceSource::MainLocal, col: 0 },
                ConstF { value: F::one() },
                ConstF { value: F::zero() },
                MulF { a: 0, b: 1 },
                AddF { a: 3, b: 2 },
                MulF { a: 0, b: 2 },
                InputLeaf { source: TraceSource::MainLocal, col: 1 },
                MulF { a: 6, b: 2 },
            ],
            constraints: [3, 4, 5, 7, 3]
                .into_iter()
                .enumerate()
                .map(|(i, root)| ConstraintRef { root, alpha_index: 17 + 3 * i as u32 })
                .collect(),
            preprocessed_width: 0,
            main_width: 2,
        };
        let infos = analyze_constraints(&dag);
        let chunk = Chunk {
            constraint_indices: (0..infos.len()).collect(),
            leafset: infos.iter().flat_map(|i| i.column_leaves.iter().copied()).collect(),
            depth_max: infos.iter().map(|i| i.depth).max().unwrap(),
            shape: ConstraintShape::General,
        };
        let plans = enumerate_lowerings(&chunk, &infos, &dag);
        let plan = plans
            .iter()
            .find_map(|p| match p {
                Lowering::Sequential(p) => Some(p),
                _ => None,
            })
            .unwrap();
        let original_max =
            liveness_allocate(&chunk, &infos, &dag, plan).values().copied().max().unwrap() + 1;
        let bc = lower_sequential(&chunk, &infos, &dag, plan);
        assert!(bc.max_reg <= original_max);
        assert_eq!(bc.instrs.len(), 2); // Only x and zero remain; the second leaf is dead.
        assert_eq!(bc.leaves.len(), 1);
        assert_eq!(bc.consts, vec![F::zero()]);
        assert_eq!(bc.asserts.iter().map(|&(_, a)| a).collect::<Vec<_>>(), [17, 20, 23, 26, 29]);
        assert_eq!(bc.asserts[0].0, bc.asserts[1].0);
        assert_eq!(bc.asserts[0].0, bc.asserts[4].0);
        assert_eq!(bc.asserts[2].0, bc.asserts[3].0);
    }
}
