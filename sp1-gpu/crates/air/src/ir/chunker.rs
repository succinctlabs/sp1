//! Seed-and-grow chunker.
//!
//! Given the per-constraint analysis, packs constraints into chunks bounded
//! by a register-pressure budget (max leafset per chunk → downstream
//! `max_reg` → MAX_REGS template tier). The objective is to minimise the
//! total column-load traffic: `Σ over chunks of |chunk.leafset|`. A column
//! shared by K chunks is fetched from memory K times, so a poor packing
//! amplifies column loads (the dominant memory traffic of the zerocheck
//! kernel).
//!
//! Heuristic: open a chunk on the largest unplaced constraint, then
//! repeatedly pull in the unplaced constraint that adds the *fewest new
//! leaves* until the budget is exhausted, then move on to the next chunk.
//! Growing one chunk to fullness before opening the next concentrates
//! column overlap far better than placing each constraint into the
//! best-so-far chunk (the earlier first-fit-decreasing heuristic): measured
//! on `RiscvAir`, seed-and-grow cuts the machine-wide column-load factor
//! from 4.4x to 1.6x at `max_leafset = 256`, and is never worse at any
//! budget.
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

/// Inner workhorse: seed-and-grow over a constraint subset.
///
/// Constraints are visited in descending-leafset order. The first unplaced
/// constraint seeds a new chunk; the chunk is then grown by repeatedly
/// pulling in the unplaced constraint that adds the fewest new leaves, until
/// no remaining constraint fits the budget. Then the next unplaced
/// constraint seeds the following chunk.
fn chunk_subset(
    constraints: &[ConstraintInfo],
    indices: &[usize],
    budget: &ChunkBudget,
) -> Vec<Chunk> {
    // Descending leafset size, then descending work — the hardest-to-place
    // constraints become seeds. `sort_by` is stable, so ties keep input
    // order, which keeps the output deterministic (the bytecode must be
    // machine-stable).
    let mut order: Vec<usize> = indices.to_vec();
    order.sort_by(|&a, &b| {
        constraints[b]
            .column_leaves
            .len()
            .cmp(&constraints[a].column_leaves.len())
            .then_with(|| constraints[b].work.cmp(&constraints[a].work))
    });

    // Every position strictly before the current seed is already placed —
    // either it was consumed as a member, or it seeded an earlier chunk —
    // so the candidate scan only needs to look forward.
    let mut placed = vec![false; order.len()];
    let mut chunks: Vec<Chunk> = Vec::new();

    for seed_pos in 0..order.len() {
        if placed[seed_pos] {
            continue;
        }
        placed[seed_pos] = true;
        let seed = &constraints[order[seed_pos]];

        let mut leafset: HashSet<ColumnLeaf> = seed.column_leaves.iter().copied().collect();
        let mut constraint_indices = vec![order[seed_pos]];
        let mut depth_max = seed.depth;
        let mut shape = seed.shape;

        // Grow: pull in the fewest-new-leaves constraint until nothing fits.
        loop {
            if constraint_indices.len() as u32 >= budget.max_constraints_per_chunk {
                break;
            }
            let mut best: Option<(usize, usize)> = None; // (pos, new_leaf_count)
            for cand_pos in (seed_pos + 1)..order.len() {
                if placed[cand_pos] {
                    continue;
                }
                let c = &constraints[order[cand_pos]];
                let new_leaves = c.column_leaves.difference(&leafset).count();
                if leafset.len() + new_leaves > budget.max_leafset as usize {
                    continue;
                }
                if best.is_none_or(|(_, bn)| new_leaves < bn) {
                    best = Some((cand_pos, new_leaves));
                    if new_leaves == 0 {
                        break; // can't beat a free add
                    }
                }
            }
            match best {
                Some((cand_pos, _)) => {
                    placed[cand_pos] = true;
                    let c = &constraints[order[cand_pos]];
                    leafset.extend(c.column_leaves.iter().copied());
                    constraint_indices.push(order[cand_pos]);
                    depth_max = depth_max.max(c.depth);
                    if !matches!(c.shape, ConstraintShape::LinearWeightedSum) {
                        shape = ConstraintShape::General;
                    }
                }
                None => break,
            }
        }

        // A lone constraint that overflows the budget on its own is the
        // scheduler's escape-valve case.
        let oversize_singleton =
            constraint_indices.len() == 1 && leafset.len() as u32 > budget.max_leafset;
        chunks.push(Chunk { constraint_indices, leafset, depth_max, shape, oversize_singleton });
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
            field: crate::ir::dag::ConstraintField::Base,
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
