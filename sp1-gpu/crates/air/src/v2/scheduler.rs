//! Per-round lowering selection.
//!
//! Given a chunk's pre-computed lowerings and the round's lane budget, picks
//! one lowering via a heuristic cost model. The model is deterministic and
//! intentionally stateless — replace with a measurement-fitted version later
//! if profiling shows mispredictions.

use crate::v2::analysis::ConstraintShape;
use crate::v2::chunker::Chunk;
use crate::v2::lowering::Lowering;

/// GPU caps that bound lowering choice. Today we only use shared-memory
/// budget; the others are placeholders for the Phase 2+ kernel code.
#[derive(Debug, Clone, Copy)]
pub struct GpuCaps {
    pub shmem_bytes_per_cta: u32,
    pub warp_size: u32,
}

impl GpuCaps {
    pub fn ampere_default() -> Self {
        Self { shmem_bytes_per_cta: 48 * 1024, warp_size: 32 }
    }
}

/// Lanes available along the data axes (row × eval_point) for this
/// `(chunk, round)`. Computed by the scheduler from per-chip row counts.
#[derive(Debug, Clone, Copy)]
pub struct LaneBudget {
    pub log_rows: u32,
    pub eval_points: u32,
}

impl LaneBudget {
    pub fn total_lanes(&self) -> u32 {
        (1u32 << self.log_rows).saturating_mul(self.eval_points)
    }
}

/// Decision returned by `pick_lowering`. Carries both the index into
/// `chunk.lowerings` and a brief reason string for telemetry.
#[derive(Debug, Clone)]
pub struct LoweringPick {
    pub lowering_idx: usize,
    pub reason: &'static str,
}

/// Heuristic cost model.
///
/// Rules, in order:
///   1. If a ColumnTile plan exists, use it. Structurally optimal for
///      `Σ β_i · leaf_i` chunks; no shared cache, lanes vary along the
///      column axis so wide chunks fill warps even at row_tile=1.
///   2. If lanes fill at least one warp on the row × eval axis, use
///      Sequential. Adding extra parallelism via other lowerings wastes
///      work without filling more lanes.
///   3. Otherwise (lane-starved): fall through to Sequential anyway.
///      Phase 5 will plug in ListScheduled / TermExpanded here.
pub fn pick_lowering(
    chunk: &Chunk,
    lowerings: &[Lowering],
    lane_budget: LaneBudget,
    _caps: GpuCaps,
) -> LoweringPick {
    // Rule 1: structural — column-tile if the chunk shape allows.
    if matches!(chunk.shape, ConstraintShape::LinearWeightedSum) {
        for (i, l) in lowerings.iter().enumerate() {
            if matches!(l, Lowering::ColumnTile(_)) {
                return LoweringPick {
                    lowering_idx: i,
                    reason: "column-tile (linear-weighted-sum shape)",
                };
            }
        }
    }

    // Rule 2: lane budget fills a warp → sequential is work-optimal.
    let total_lanes = lane_budget.total_lanes();
    let reason = if total_lanes >= _caps.warp_size {
        "sequential (lanes fill warp)"
    } else {
        // Rule 3: lane-starved; Sequential is the v1 fallback. Phase 5 will
        // route to ListScheduled or TermExpanded here.
        "sequential (lane-starved; Phase 5 path)"
    };
    for (i, l) in lowerings.iter().enumerate() {
        if matches!(l, Lowering::Sequential(_)) {
            return LoweringPick { lowering_idx: i, reason };
        }
    }
    // Should not reach here — Sequential is always emitted.
    LoweringPick { lowering_idx: 0, reason: "fallback (no sequential found)" }
}
