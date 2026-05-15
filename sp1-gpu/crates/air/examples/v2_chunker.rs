//! Phase 1 validation: run the v2 builder + analysis + chunker on every chip
//! in `RiscvAir` and reproduce the chunk-count and union-leafset distributions
//! we saw in the earlier `analyze_chips` study.
//!
//! The numbers here should match v1 to within rounding; differences are a
//! warning sign the v2 path lost something.

use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_air::v2::{
    analyze_constraints, build_dag, chunk_dag, Chunk, ChunkBudget, ConstraintShape,
};
use sp1_gpu_air::F;
use sp1_hypercube::air::MachineAir;

const FOCUS: &[&str] = &[
    "KeccakPermute",
    "Secp256k1AddAssign",
    "Secp256k1DoubleAssign",
    "Bn254AddAssign",
    "Bls12381AddAssign",
    "Bls12381FpOpAssign",
    "EdAddAssign",
    "Add",
    "Bitwise",
    "Mul",
    "Branch",
    "Global",
];

fn main() {
    let machine = RiscvAir::<F>::machine();

    let budgets = [
        ChunkBudget { max_leafset: 64, max_constraints_per_chunk: 1024 },
        ChunkBudget { max_leafset: 128, max_constraints_per_chunk: 1024 },
        ChunkBudget { max_leafset: 256, max_constraints_per_chunk: 1024 },
    ];

    for budget in &budgets {
        println!("\n=== budget: max_leafset={} ===", budget.max_leafset);
        println!(
            "{:<28} {:>5} {:>6} {:>5} {:>6} {:>5} {:>5} {:>5} {:>7} {:>3}",
            "chip", "cons", "nodes", "depth", "nChnk", "maxU", "p50U", "meanC", "linear%", "ovr"
        );
        for chip in machine.chips() {
            let name = chip.name();
            if !FOCUS.iter().any(|f| name == *f) {
                continue;
            }
            let dag = build_dag(chip.air.as_ref());
            let infos = analyze_constraints(&dag);
            let chunks = chunk_dag(&infos, budget);
            print_row(name, &infos, &chunks);
        }
    }

    // Show that GKR-shape detection works: synthesize one chip's worth of
    // LinearWeightedSum constraints and confirm the chunker tags them.
    println!("\n=== shape-detection report ===");
    let machine = RiscvAir::<F>::machine();
    for chip in machine.chips() {
        let dag = build_dag(chip.air.as_ref());
        let infos = analyze_constraints(&dag);
        let n_linear =
            infos.iter().filter(|c| matches!(c.shape, ConstraintShape::LinearWeightedSum)).count();
        if n_linear > 0 {
            println!(
                "  {:<32} {:>4} / {:<4} constraints are LinearWeightedSum",
                chip.name(),
                n_linear,
                infos.len()
            );
        }
    }
}

fn print_row(name: &str, infos: &[sp1_gpu_air::v2::ConstraintInfo], chunks: &[Chunk]) {
    let cons = infos.len();
    let nodes: usize = infos.iter().map(|c| c.total_nodes as usize).sum();
    let depth_max = infos.iter().map(|c| c.depth).max().unwrap_or(0);

    let unions: Vec<usize> = chunks.iter().map(|c| c.leafset.len()).collect();
    let max_u = unions.iter().copied().max().unwrap_or(0);
    let p50_u = pct(&unions, 0.5);
    let mean_c = if chunks.is_empty() {
        0.0
    } else {
        chunks.iter().map(|c| c.constraint_indices.len()).sum::<usize>() as f64
            / chunks.len() as f64
    };
    let linear_pct = if chunks.is_empty() {
        0
    } else {
        100 * chunks
            .iter()
            .filter(|c| matches!(c.shape, ConstraintShape::LinearWeightedSum))
            .count()
            / chunks.len()
    };
    let oversize = chunks.iter().filter(|c| c.oversize_singleton).count();

    println!(
        "{:<28} {:>5} {:>6} {:>5} {:>6} {:>5} {:>5} {:>5.1} {:>6}% {:>3}",
        truncate(name, 28),
        cons,
        nodes,
        depth_max,
        chunks.len(),
        max_u,
        p50_u,
        mean_c,
        linear_pct,
        oversize,
    );
}

fn pct<T: Ord + Copy + Default>(xs: &[T], p: f64) -> T {
    if xs.is_empty() {
        return T::default();
    }
    let mut s = xs.to_vec();
    s.sort();
    let idx = ((s.len() as f64) * p).floor() as usize;
    s[idx.min(s.len() - 1)]
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}...", &s[..n.saturating_sub(3)])
    }
}
