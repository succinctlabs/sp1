//! Greedy first-fit-decreasing chunker.
//!
//! Given the per-constraint analysis, packs constraints into chunks bounded
//! by a register-pressure
//! budget (max leafset per chunk → downstream `max_reg` → MAX_REGS template
//! tier). Heuristic: sort constraints by descending leafset size, then for
//! each, pick the chunk that minimizes the number of NEW unique leaves
//! introduced.
//!
//! If a single constraint already exceeds the budget, it becomes its own
//! chunk — flagged for the scheduler to route to the escape-valve lowering.

use std::collections::HashSet;

use crate::ir::analysis::{ColumnLeaf, ConstraintInfo, ConstraintShape};

/// Hard caps the chunker won't exceed when adding a constraint to an existing chunk.
///
/// Both fields correspond to real per-kernel resources:
///
/// * `max_leafset` — the chunk's column-leaf footprint. The fused sequential
///   kernel materialises one register slot per leaf and reuses them across
///   every assertion in the chunk; the chunk's downstream `max_reg` (peak
///   live count in `K regs[MAX_REGS][3]`) is `leafset_size + small_overhead`,
///   so this directly controls which `MAX_REGS={32,64,128,256,512,1024}`
///   template tier the chunk falls into. Cross a tier and the per-thread
///   `regs[]` array doubles, spilling out of the L1-cached local-memory
///   window.
/// * `max_constraints_per_chunk` — caps the size of the chunk's `instrs[]`
///   and `assert_regs[]` arrays in global memory. Rarely the binding
///   constraint in practice; lives here so a pathological AIR can't generate
///   an unbounded instruction stream per chunk.
#[derive(Debug, Clone, Copy)]
pub struct ChunkBudget {
    pub max_leafset: u32,
    pub max_constraints_per_chunk: u32,
}

impl ChunkBudget {
    /// Defaults derived from sweep across real-RSP shards (n_chips ∈ {6,7,34})
    /// and synthetic core / all-chips clusters at 2^25..2^27.
    ///
    /// `max_leafset = 64` keeps each chunk's downstream `max_reg` ≲ 128, so
    /// the fused sequential kernel runs on the `MAX_REGS=128` template — its
    /// per-thread `regs[]` footprint stays small enough to remain L1-resident
    /// across the active block set. Pushing the leafset higher cross-tiers
    /// into `MAX_REGS={256,512}`, doubling the per-thread footprint and
    /// turning the kernel memory-latency-bound; pushing lower over-fragments
    /// big chips so shared columns get redundantly reloaded across chunks.
    pub fn recommended() -> Self {
        let env_u32 = |k: &str, default: u32| -> u32 {
            std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
        };
        Self {
            max_leafset: env_u32("CHUNKER_MAX_LEAFSET", 64),
            max_constraints_per_chunk: env_u32("CHUNKER_MAX_CONSTRAINTS", 512),
        }
    }
}

/// A grouping of constraints sharing a leaf cache.
#[derive(Debug)]
pub struct Chunk {
    /// Indices into the input `&[ConstraintInfo]`.
    pub constraint_indices: Vec<usize>,
    /// Union of column leaves across contained constraints.
    pub leafset: HashSet<ColumnLeaf>,
    /// Max depth among contained constraints.
    pub depth_max: u32,
    /// Aggregate shape — `LinearWeightedSum` iff every contained constraint
    /// is itself `LinearWeightedSum`. The scheduler uses this to elect the
    /// column-tile lowering.
    pub shape: ConstraintShape,
    /// True iff this chunk is a single constraint that exceeded the budget
    /// on its own. The scheduler must route it through the escape-valve
    /// path (global-scratch leaves).
    pub oversize_singleton: bool,
}

/// Shape-aware chunker.
///
/// Segregates `LinearWeightedSum` constraints from `General` ones, then chunks
/// each subset independently. Reason: a chunk's `shape` is `LinearWeightedSum`
/// only if *every* member is `LinearWeightedSum`; mixing kills column-tile
/// dispatch eligibility. So we don't let the leaf-greedy heuristic mix shapes.
///
/// Both subsets are packed with the same budget. Future work: linear-sum
/// chunks could use a larger leaf budget since ColumnTile doesn't pay for a
/// shared-mem cache, but Phase 3 keeps it uniform.
pub fn chunk_dag(constraints: &[ConstraintInfo], budget: &ChunkBudget) -> Vec<Chunk> {
    let (linear, general): (Vec<_>, Vec<_>) = (0..constraints.len())
        .filter(|&i| {
            let c = &constraints[i];
            !c.column_leaves.is_empty() || c.work > 0
        })
        .partition(|&i| matches!(constraints[i].shape, ConstraintShape::LinearWeightedSum));

    let mut chunks = Vec::new();
    chunks.extend(chunk_subset(constraints, &linear, budget));
    chunks.extend(chunk_subset(constraints, &general, budget));
    chunks
}

/// Inner workhorse: greedy first-fit-decreasing over a constraint subset.
fn chunk_subset(
    constraints: &[ConstraintInfo],
    indices: &[usize],
    budget: &ChunkBudget,
) -> Vec<Chunk> {
    // First-fit decreasing: sort indices by descending leafset size, then by
    // descending work.
    let mut order: Vec<usize> = indices.to_vec();
    order.sort_by(|&a, &b| {
        constraints[b]
            .column_leaves
            .len()
            .cmp(&constraints[a].column_leaves.len())
            .then_with(|| constraints[b].work.cmp(&constraints[a].work))
    });

    let mut chunks: Vec<Chunk> = Vec::new();
    for ci in order {
        let c = &constraints[ci];

        // Find an existing chunk that can absorb this constraint with the
        // fewest new unique leaves.
        let mut best: Option<(usize, usize)> = None; // (chunk_idx, new_leaf_count)
        for (i, chunk) in chunks.iter().enumerate() {
            // Quick rejection: would exceed constraint cap.
            if chunk.constraint_indices.len() as u32 + 1 > budget.max_constraints_per_chunk {
                continue;
            }
            // Compute the prospective union size.
            let new_leaves = c.column_leaves.difference(&chunk.leafset).count();
            let new_union = chunk.leafset.len() + new_leaves;
            if new_union as u32 > budget.max_leafset {
                continue;
            }
            if best.is_none_or(|(_, bn)| new_leaves < bn) {
                best = Some((i, new_leaves));
            }
        }

        match best {
            Some((idx, _)) => {
                let chunk = &mut chunks[idx];
                for &leaf in &c.column_leaves {
                    chunk.leafset.insert(leaf);
                }
                chunk.constraint_indices.push(ci);
                chunk.depth_max = chunk.depth_max.max(c.depth);
                if !matches!(c.shape, ConstraintShape::LinearWeightedSum) {
                    chunk.shape = ConstraintShape::General;
                }
            }
            None => {
                // Could not fit into any existing chunk → emit a fresh one.
                // If the constraint alone exceeds the budget, flag it.
                let oversize_singleton = c.column_leaves.len() as u32 > budget.max_leafset;
                let mut leafset = HashSet::with_capacity(c.column_leaves.len());
                for &leaf in &c.column_leaves {
                    leafset.insert(leaf);
                }
                chunks.push(Chunk {
                    constraint_indices: vec![ci],
                    leafset,
                    depth_max: c.depth,
                    shape: c.shape,
                    oversize_singleton,
                });
            }
        }
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::dag::TraceSource;

    fn cinfo(idx: usize, cols: &[u32], work: u32, depth: u32) -> ConstraintInfo {
        let column_leaves = cols
            .iter()
            .copied()
            .map(|c| ColumnLeaf { source: TraceSource::MainLocal, col: c })
            .collect();
        ConstraintInfo {
            constraint_idx: idx,
            root: 0,
            alpha_index: idx as u32,
            total_nodes: 0,
            work,
            depth,
            column_leaves,
            shape: ConstraintShape::General,
        }
    }

    #[test]
    fn small_constraints_pack_into_one_chunk() {
        let c = vec![cinfo(0, &[0, 1, 2], 5, 3), cinfo(1, &[0, 1, 3], 5, 3)];
        let chunks = chunk_dag(&c, &ChunkBudget { max_leafset: 16, max_constraints_per_chunk: 16 });
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].leafset.len(), 4);
        assert_eq!(chunks[0].constraint_indices.len(), 2);
    }

    #[test]
    fn budget_forces_split() {
        let c = vec![
            cinfo(0, &(0..10).collect::<Vec<_>>(), 5, 3),
            cinfo(1, &(10..20).collect::<Vec<_>>(), 5, 3),
        ];
        let chunks = chunk_dag(&c, &ChunkBudget { max_leafset: 12, max_constraints_per_chunk: 16 });
        assert_eq!(chunks.len(), 2);
    }

    #[test]
    fn oversize_singleton_flagged() {
        let c = vec![cinfo(0, &(0..100).collect::<Vec<_>>(), 50, 5)];
        let chunks = chunk_dag(&c, &ChunkBudget { max_leafset: 16, max_constraints_per_chunk: 16 });
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].oversize_singleton);
    }
}
