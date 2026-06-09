#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::doc_lazy_continuation
)]
//! Arithmetization / chunking efficiency report.
//!
//! For every `RiscvAir` chip, measure how many column loads the chunker emits
//! relative to how many distinct columns the chip's constraints actually
//! reference. This is the direct measure of *chunking quality*.
//!
//! Definitions (all at `ColumnLeaf` granularity — a `(source, col)` pair, so a
//! column read both as `MainLocal` and `MainNext` counts as two):
//!
//! * `refd` — distinct column leaves referenced anywhere in the chip's
//!   constraints (the union over all chunks). Each must be loaded at least
//!   once; this is the irreducible floor.
//! * `loaded` — `Σ over chunks of |chunk.leafset|`. The fused sequential kernel
//!   materialises one register slot per leaf *per chunk* and reuses it within
//!   the chunk, so a column shared by K chunks is fetched from memory K times.
//! * `reload` — `loaded / refd`. 1.00 = perfect (every column loaded once);
//!   >1.00 = the chunk split forces redundant column re-fetches.
//!
//! Separately, against the chip's physical width (`main + preprocessed`
//! columns), `touch = refd / (2 × width)` shows what fraction of the chip's
//! leaf space (each column × {local, next}) the arithmetization actually
//! reads — a constraint-density signal, not a chunking one.
//!
//! Run with: cargo run --release --example chunk_efficiency -p sp1-gpu-air

use slop_air::BaseAir;
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_air::ir::{analyze_constraints, build_dag, chunk_dag, Chunk, ChunkBudget};
use sp1_gpu_air::F;
use sp1_hypercube::air::MachineAir;

struct Row {
    name: String,
    width: usize,  // physical columns: main + preprocessed
    refd: usize,   // distinct leaves referenced
    loaded: usize, // Σ |chunk leafset|
    nchunk: usize,
    ovr: usize, // chunks that are a single over-budget constraint
}

fn measure(name: &str, width: usize, chunks: &[Chunk]) -> Row {
    let loaded: usize = chunks.iter().map(|c| c.leafset.len()).sum();
    let ovr = chunks.iter().filter(|c| c.oversize_singleton).count();
    let mut refd_set = std::collections::HashSet::new();
    for chunk in chunks {
        for &leaf in &chunk.leafset {
            refd_set.insert(leaf);
        }
    }
    Row { name: name.to_string(), width, refd: refd_set.len(), loaded, nchunk: chunks.len(), ovr }
}

fn main() {
    let machine = RiscvAir::<F>::machine();

    let budgets = [
        ChunkBudget { max_leafset: 64, max_constraints_per_chunk: 1024 },
        ChunkBudget { max_leafset: 128, max_constraints_per_chunk: 1024 },
        ChunkBudget { max_leafset: 256, max_constraints_per_chunk: 1024 },
    ];

    for budget in &budgets {
        let mut rows: Vec<Row> = Vec::new();
        for chip in machine.chips() {
            let width = chip.width() + chip.preprocessed_width();
            let dag = build_dag(chip.air.as_ref());
            let infos = analyze_constraints(&dag);
            let chunks = chunk_dag(&infos, budget);
            if chunks.is_empty() {
                continue; // chip with no column-reading constraints
            }
            rows.push(measure(chip.name(), width, &chunks));
        }
        // Heaviest column-load chips first.
        rows.sort_by_key(|r| std::cmp::Reverse(r.loaded));

        println!("\n=== chunk efficiency — max_leafset={} ===", budget.max_leafset);
        println!(
            "{:<28} {:>5} {:>6} {:>6} {:>4} {:>6} {:>8} {:>7}",
            "chip", "width", "refd", "nChnk", "ovr", "loaded", "reload x", "touch %"
        );
        let (mut tot_refd, mut tot_loaded, mut tot_chunks, mut tot_ovr) = (0usize, 0, 0, 0);
        let mut tot_leafspace = 0usize;
        for r in &rows {
            let reload = r.loaded as f64 / r.refd.max(1) as f64;
            let touch = 100.0 * r.refd as f64 / (2 * r.width).max(1) as f64;
            println!(
                "{:<28} {:>5} {:>6} {:>6} {:>4} {:>6} {:>8.3} {:>6.1}%",
                truncate(&r.name, 28),
                r.width,
                r.refd,
                r.nchunk,
                r.ovr,
                r.loaded,
                reload,
                touch,
            );
            tot_refd += r.refd;
            tot_loaded += r.loaded;
            tot_chunks += r.nchunk;
            tot_ovr += r.ovr;
            tot_leafspace += 2 * r.width;
        }
        println!("{:-<28}", "");
        let machine_reload = tot_loaded as f64 / tot_refd.max(1) as f64;
        let machine_touch = 100.0 * tot_refd as f64 / tot_leafspace.max(1) as f64;
        println!(
            "{:<28} {:>5} {:>6} {:>6} {:>4} {:>6} {:>8.3} {:>6.1}%",
            format!("TOTAL ({} chips)", rows.len()),
            "",
            tot_refd,
            tot_chunks,
            tot_ovr,
            tot_loaded,
            machine_reload,
            machine_touch,
        );
        let waste = tot_loaded.saturating_sub(tot_refd);
        println!(
            "  machine-wide: {tot_loaded} column loads for {tot_refd} distinct columns \
             → {waste} redundant re-fetches ({:.1}% overhead)",
            100.0 * waste as f64 / tot_refd.max(1) as f64,
        );
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}...", &s[..n.saturating_sub(3)])
    }
}
