//! Phase 1 capstone: build a chip's DAG, chunk it, enumerate lowerings, and
//! show what the heuristic cost model picks per round across the sumcheck.
//!
//! Validates that:
//!   - column-tile is elected for linear-weighted-sum chunks
//!   - sequential is elected when row × eval ≥ warp_size
//!   - lane-starved late rounds gracefully fall through to sequential
//!     (the placeholder until Phase 5)

use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_air::v2::{
    analyze_constraints, build_dag, chunk_dag, enumerate_lowerings, pick_lowering, ChunkBudget,
    GpuCaps, LaneBudget, Lowering,
};
use sp1_gpu_air::F;
use sp1_hypercube::air::MachineAir;

fn main() {
    let machine = RiscvAir::<F>::machine();
    let caps = GpuCaps::ampere_default();
    let budget = ChunkBudget { max_leafset: 64, max_constraints_per_chunk: 1024 };

    // Simulate per-round lane budgets for a few chip log-row-counts and report
    // per-(chunk, round) decisions aggregated by lowering kind.
    let scenarios: &[(&str, u32)] = &[
        ("KeccakPermute", 14), // ~16k initial rows
        ("Bls12381FpOpAssign", 8),
        ("Add", 18),
        ("Bitwise", 18),
        ("Branch", 16),
    ];

    for &(chip_name, log_rows) in scenarios {
        let chip = match machine.chips().iter().find(|c| c.name() == chip_name) {
            Some(c) => c,
            None => continue,
        };
        let dag = build_dag(chip.air.as_ref());
        let infos = analyze_constraints(&dag);
        let chunks = chunk_dag(&infos, &budget);
        let plans: Vec<Vec<Lowering>> =
            chunks.iter().map(|c| enumerate_lowerings(c, &infos, &dag)).collect();

        println!(
            "\n=== {} (initial log_rows = {}, chunks = {}) ===",
            chip_name,
            log_rows,
            chunks.len()
        );
        println!(
            "{:>4} {:>10} {:>10} {:>10} {:>10}",
            "rnd", "lanes", "sequential", "columntile", "starved"
        );
        for r in 0..=log_rows {
            let cur_log_rows = log_rows.saturating_sub(r);
            let lane_budget = LaneBudget { log_rows: cur_log_rows, eval_points: 3 };
            let lanes = lane_budget.total_lanes();

            let mut counts = [0u32; 3]; // [sequential_warpfull, columntile, starved]
            for (chunk, lowerings) in chunks.iter().zip(plans.iter()) {
                let pick = pick_lowering(chunk, lowerings, lane_budget, caps);
                match &lowerings[pick.lowering_idx] {
                    Lowering::ColumnTile(_) => counts[1] += 1,
                    Lowering::Sequential(_) => {
                        if lanes >= caps.warp_size {
                            counts[0] += 1;
                        } else {
                            counts[2] += 1;
                        }
                    }
                    _ => {}
                }
            }
            println!(
                "{:>4} {:>10} {:>10} {:>10} {:>10}",
                r, lanes, counts[0], counts[1], counts[2]
            );
        }
    }
}
