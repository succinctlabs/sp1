//! Empirical analysis of AIR constraint shapes per chip.
//!
//! For each chip in `RiscvAir::machine()`, runs the symbolic builder to capture the
//! pre-optimization `Instruction32` tape per AIR-block, walks each FAssertZero back to
//! its transitive column-leaf set via SSA def-use, and reports:
//!
//!   - per-constraint column-leaf count distribution (max, p99, p50, mean)
//!   - chip's main + preprocessed width
//!   - cross-constraint overlap: |union(leaves)| / sum(|leaves|)
//!   - shared-memory budget check: max single-constraint leafset × 8B × ROW_TILE
//!
//! Run with: cargo run --release --example analyze_chips -p sp1-gpu-air

use std::collections::{HashMap, HashSet};

use slop_matrix::dense::DenseMatrix;
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_air::air_block::BlockAir;
use sp1_gpu_air::instruction::{Instruction32, Opcode};
use sp1_gpu_air::symbolic_var_f::SymbolicVarF;
use sp1_gpu_air::{
    SymbolicProverFolder, CUDA_P3_EVAL_CODE, CUDA_P3_EVAL_EF_CONSTANTS, CUDA_P3_EVAL_F_CONSTANTS,
    CUDA_P3_EVAL_LOCK, CUDA_P3_EVAL_RESET, F,
};
use sp1_hypercube::air::MachineAir;
use sp1_hypercube::{AirOpenedValues, PROOF_MAX_NUM_PVS};

#[derive(Default, Clone)]
struct ConstraintStats {
    /// Distinct (variant, idx) pairs in the transitive closure that are column refs.
    /// Variants 2/3 = preprocessed local/next, 4/5 = main local/next.
    column_leaves: HashSet<(u8, u32)>,
    /// Instructions traversed in the transitive closure.
    op_count: usize,
    /// Depth of the longest dependency chain.
    depth: usize,
    /// All distinct leaves (including public values, IsFirstRow, etc.).
    all_leaves: HashSet<(u8, u32)>,
}

struct ChipStats {
    name: String,
    n_blocks: usize,
    n_constraints: usize,
    prep_width: u32,
    main_width: u32,
    /// All distinct column refs touched across the entire chip program.
    chip_columns_touched: HashSet<(u8, u32)>,
    constraints: Vec<ConstraintStats>,
}

fn main() {
    let machine = RiscvAir::<F>::machine();

    // Header
    println!(
        "{:<46} {:>5} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {:>9} {:>7}",
        "chip",
        "blks",
        "cons",
        "main",
        "prep",
        "touch",
        "maxL",
        "p99L",
        "p50L",
        "meanOps",
        "overlap",
    );
    println!("{}", "-".repeat(130));

    let mut all_chips = Vec::new();
    for chip in machine.chips() {
        let _guard = CUDA_P3_EVAL_LOCK.lock().unwrap();
        let stats = analyze_chip(chip.name(), chip.air.as_ref());
        print_chip_row(&stats);
        all_chips.push(stats);
    }

    // Detailed breakdown for the chips that matter most for the design question.
    let focus: &[&str] = &[
        "KeccakP",
        "Secp256k1Add",
        "Secp256k1Double",
        "Bn254Add",
        "Bn254Double",
        "Add",
        "AddUser",
        "Bitwise",
        "BitwiseUser",
        "Mul",
        "MulUser",
        "Sll",
        "Memory",
        "MemoryGlobal",
        "Branch",
    ];
    for stats in all_chips.iter().filter(|s| focus.contains(&s.name.as_str())) {
        print_chip_detail(stats);
    }

    // Aggregate summary: how many chips have any single constraint exceeding given thresholds?
    println!("\nshmem stress: count of chips whose worst constraint has |leaves| ≥ N");
    for &thresh in &[8u32, 16, 32, 64, 128, 256, 512] {
        let n = all_chips
            .iter()
            .filter(|s| s.constraints.iter().any(|c| c.column_leaves.len() as u32 >= thresh))
            .count();
        println!("  >= {:>4} : {:>3} chips", thresh, n);
    }

    // ===== CHUNKER SIMULATION =====
    // For each budget B, run a greedy first-fit-decreasing chunker on each chip and
    // report how many chunks are produced + leaf-union distribution per chunk.
    println!("\n\n=== Chunker simulation (greedy first-fit-decreasing by |leaves|) ===");
    for &budget in &[64usize, 128, 256, 512] {
        println!(
            "\n-- budget = {} leaves/chunk --\n{:<38} {:>6} {:>6} {:>7} {:>7} {:>7} {:>7} {:>9}",
            budget, "chip", "cons", "nChnk", "maxU", "p99U", "p50U", "meanC", "row_tile@48KB"
        );
        for s in &all_chips {
            if s.n_constraints == 0 {
                continue;
            }
            let chunks = greedy_chunk(&s.constraints, budget);
            let unions: Vec<usize> = chunks.iter().map(|c| c.leaves.len()).collect();
            let con_per_chunk: Vec<usize> = chunks.iter().map(|c| c.n_constraints).collect();
            let max_u = unions.iter().copied().max().unwrap_or(0);
            let p99_u = pct(&unions, 0.99);
            let p50_u = pct(&unions, 0.5);
            let mean_c = if con_per_chunk.is_empty() {
                0.0
            } else {
                con_per_chunk.iter().sum::<usize>() as f64 / con_per_chunk.len() as f64
            };
            // shmem fit: 48 KB / (max union × 8 bytes/leaf)
            let row_tile = if max_u == 0 { 0 } else { (48 * 1024) / (max_u * 8) };
            println!(
                "{:<38} {:>6} {:>6} {:>7} {:>7} {:>7} {:>7.1} {:>9}",
                truncate(&s.name, 38),
                s.n_constraints,
                chunks.len(),
                max_u,
                p99_u,
                p50_u,
                mean_c,
                row_tile,
            );
        }
    }
}

struct ChunkInfo {
    leaves: HashSet<(u8, u32)>,
    n_constraints: usize,
    op_count: usize,
}

fn greedy_chunk(constraints: &[ConstraintStats], budget: usize) -> Vec<ChunkInfo> {
    // First-fit decreasing by leaf count, breaking ties by op count.
    // For each constraint, place it in the existing chunk that:
    //   (a) can fit it (union <= budget after add)
    //   (b) minimizes new unique leaves added
    // If none fits, start a new chunk.
    let mut sorted: Vec<&ConstraintStats> = constraints.iter().collect();
    sorted.sort_by(|a, b| {
        b.column_leaves.len().cmp(&a.column_leaves.len()).then_with(|| b.op_count.cmp(&a.op_count))
    });

    let mut chunks: Vec<ChunkInfo> = Vec::new();
    for c in sorted {
        // Skip empty constraints.
        if c.column_leaves.is_empty() && c.op_count == 0 {
            continue;
        }

        let mut best: Option<(usize, usize, usize)> = None; // (idx, new_leaves, new_union)
        for (i, chunk) in chunks.iter().enumerate() {
            let new_leaves = c.column_leaves.difference(&chunk.leaves).count();
            let new_union = chunk.leaves.len() + new_leaves;
            if new_union <= budget {
                match best {
                    None => best = Some((i, new_leaves, new_union)),
                    Some((_, bnew, _)) if new_leaves < bnew => {
                        best = Some((i, new_leaves, new_union))
                    }
                    _ => {}
                }
            }
        }
        match best {
            Some((idx, _, _)) => {
                let chunk = &mut chunks[idx];
                for &leaf in &c.column_leaves {
                    chunk.leaves.insert(leaf);
                }
                chunk.n_constraints += 1;
                chunk.op_count += c.op_count;
            }
            None => {
                // Single-constraint chunk; if it exceeds budget by itself, still emit it
                // (this is the "escape valve C needed" case — track it).
                let mut leaves = HashSet::new();
                for &leaf in &c.column_leaves {
                    leaves.insert(leaf);
                }
                chunks.push(ChunkInfo { leaves, n_constraints: 1, op_count: c.op_count });
            }
        }
    }
    chunks
}

fn print_chip_row(stats: &ChipStats) {
    let leaf_counts: Vec<usize> = stats.constraints.iter().map(|c| c.column_leaves.len()).collect();
    let max_l = leaf_counts.iter().copied().max().unwrap_or(0);
    let p99_l = pct(&leaf_counts, 0.99);
    let p50_l = pct(&leaf_counts, 0.5);
    let mean_ops = if stats.constraints.is_empty() {
        0.0
    } else {
        stats.constraints.iter().map(|c| c.op_count).sum::<usize>() as f64
            / stats.constraints.len() as f64
    };
    let touched = stats.chip_columns_touched.len();
    let sum_leaves: usize = leaf_counts.iter().sum();
    let overlap = if sum_leaves == 0 {
        0.0
    } else {
        // 1.0 = no sharing (sum == union); high = lots of sharing.
        sum_leaves as f64 / touched.max(1) as f64
    };
    println!(
        "{:<46} {:>5} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {:>9.1} {:>7.2}",
        truncate(&stats.name, 46),
        stats.n_blocks,
        stats.n_constraints,
        stats.main_width,
        stats.prep_width,
        touched,
        max_l,
        p99_l,
        p50_l,
        mean_ops,
        overlap,
    );
}

fn print_chip_detail(stats: &ChipStats) {
    println!("\n=== {} ===", stats.name);
    println!(
        "  blocks={}  constraints={}  main_width={}  prep_width={}  columns_touched={}",
        stats.n_blocks,
        stats.n_constraints,
        stats.main_width,
        stats.prep_width,
        stats.chip_columns_touched.len(),
    );
    // Histogram of per-constraint leaf counts.
    let mut buckets: [(u32, u32, u32); 9] = [
        (0, 1, 0),
        (2, 4, 0),
        (5, 8, 0),
        (9, 16, 0),
        (17, 32, 0),
        (33, 64, 0),
        (65, 128, 0),
        (129, 256, 0),
        (257, u32::MAX, 0),
    ];
    for c in &stats.constraints {
        let n = c.column_leaves.len() as u32;
        for b in buckets.iter_mut() {
            if n >= b.0 && n <= b.1 {
                b.2 += 1;
                break;
            }
        }
    }
    println!("  per-constraint |column-leaves| histogram:");
    for (lo, hi, cnt) in buckets {
        if cnt == 0 {
            continue;
        }
        let label =
            if hi == u32::MAX { format!("{:>4}+", lo) } else { format!("{:>4}-{:<4}", lo, hi) };
        println!("    {} : {}", label, cnt);
    }
    // Op count stats.
    let ops: Vec<usize> = stats.constraints.iter().map(|c| c.op_count).collect();
    println!(
        "  op count: min={}  p50={}  p99={}  max={}",
        ops.iter().copied().min().unwrap_or(0),
        pct(&ops, 0.5),
        pct(&ops, 0.99),
        ops.iter().copied().max().unwrap_or(0),
    );
    // Depth stats.
    let depths: Vec<usize> = stats.constraints.iter().map(|c| c.depth).collect();
    println!(
        "  depth   : min={}  p50={}  p99={}  max={}",
        depths.iter().copied().min().unwrap_or(0),
        pct(&depths, 0.5),
        pct(&depths, 0.99),
        depths.iter().copied().max().unwrap_or(0),
    );
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}...", &s[..n.saturating_sub(3)])
    }
}

fn pct<T: Ord + Copy + Default>(xs: &[T], p: f64) -> T {
    if xs.is_empty() {
        return T::default();
    }
    let mut sorted: Vec<T> = xs.to_vec();
    sorted.sort();
    let idx = ((sorted.len() as f64) * p).floor() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn analyze_chip<A>(name: &str, air: &A) -> ChipStats
where
    A: for<'a> BlockAir<SymbolicProverFolder<'a>>,
{
    let prep_width = air.preprocessed_width() as u32;
    let main_width = air.width() as u32;

    let prep_vars: Vec<SymbolicVarF> =
        (0..prep_width).map(SymbolicVarF::preprocessed_local).collect();
    let main_vars: Vec<SymbolicVarF> = (0..main_width).map(SymbolicVarF::main_local).collect();
    let prep_matrix = DenseMatrix::new(prep_vars, prep_width as usize);
    let main_matrix = DenseMatrix::new(main_vars, main_width as usize);

    let preprocessed_view = AirOpenedValues { local: prep_matrix.values.clone() };
    let main_view = AirOpenedValues { local: main_matrix.values.clone() };
    let public_values =
        (0..PROOF_MAX_NUM_PVS as u32).map(SymbolicVarF::public_value).collect::<Vec<_>>();

    // Reset before chip starts.
    CUDA_P3_EVAL_RESET();
    *CUDA_P3_EVAL_F_CONSTANTS.lock().unwrap() = Vec::new();
    *CUDA_P3_EVAL_EF_CONSTANTS.lock().unwrap() = Vec::new();

    let mut folder = SymbolicProverFolder {
        preprocessed: preprocessed_view.view(),
        main: main_view.view(),
        public_values: &public_values,
        num_constraints: 0,
    };

    let mut stats = ChipStats {
        name: name.to_string(),
        n_blocks: air.num_blocks(),
        n_constraints: 0,
        prep_width,
        main_width,
        chip_columns_touched: HashSet::new(),
        constraints: Vec::new(),
    };

    for i in 0..air.num_blocks() {
        air.eval_block(&mut folder, i);
        let code = CUDA_P3_EVAL_CODE.lock().unwrap().to_vec();
        CUDA_P3_EVAL_RESET();
        *CUDA_P3_EVAL_F_CONSTANTS.lock().unwrap() = Vec::new();
        *CUDA_P3_EVAL_EF_CONSTANTS.lock().unwrap() = Vec::new();

        let block_constraints = analyze_tape(&code);
        for c in &block_constraints {
            for &leaf in &c.column_leaves {
                stats.chip_columns_touched.insert(leaf);
            }
        }
        stats.constraints.extend(block_constraints);
    }

    stats.n_constraints = stats.constraints.len();
    stats
}

fn analyze_tape(code: &[Instruction32]) -> Vec<ConstraintStats> {
    // Build def map. Each non-Assert instruction defines its `a` register.
    let mut def_of: HashMap<u32, usize> = HashMap::with_capacity(code.len());
    for (i, instr) in code.iter().enumerate() {
        let op = Opcode::from(instr.opcode);
        if !matches!(op, Opcode::FAssertZero | Opcode::EAssertZero | Opcode::Empty) {
            def_of.insert(instr.a, i);
        }
    }

    let mut out = Vec::new();
    for instr in code.iter() {
        let op = Opcode::from(instr.opcode);
        if !matches!(op, Opcode::FAssertZero | Opcode::EAssertZero) {
            continue;
        }
        out.push(collect_for_assert(code, &def_of, instr.a));
    }
    out
}

fn collect_for_assert(
    code: &[Instruction32],
    def_of: &HashMap<u32, usize>,
    root: u32,
) -> ConstraintStats {
    let mut visited: HashMap<u32, usize> = HashMap::new(); // reg -> depth
    let mut stats = ConstraintStats::default();
    // DFS with depth tracking.
    fn walk(
        code: &[Instruction32],
        def_of: &HashMap<u32, usize>,
        reg: u32,
        visited: &mut HashMap<u32, usize>,
        stats: &mut ConstraintStats,
    ) -> usize {
        if let Some(&d) = visited.get(&reg) {
            return d;
        }
        let idx = match def_of.get(&reg) {
            Some(&i) => i,
            None => {
                visited.insert(reg, 0);
                return 0;
            }
        };
        stats.op_count += 1;
        let instr = &code[idx];
        let op = Opcode::from(instr.opcode);
        let (b_kind, c_kind) = operand_kinds(op);
        let mut max_child = 0usize;
        if let Some(k) = b_kind {
            max_child = max_child.max(handle_operand(
                code,
                def_of,
                k,
                instr.b_variant,
                instr.b,
                visited,
                stats,
            ));
        }
        if let Some(k) = c_kind {
            max_child = max_child.max(handle_operand(
                code,
                def_of,
                k,
                instr.c_variant,
                instr.c,
                visited,
                stats,
            ));
        }
        let d = 1 + max_child;
        visited.insert(reg, d);
        d
    }
    let depth = walk(code, def_of, root, &mut visited, &mut stats);
    stats.depth = depth;
    stats
}

fn handle_operand(
    code: &[Instruction32],
    def_of: &HashMap<u32, usize>,
    kind: Kind,
    variant: u8,
    data: u32,
    visited: &mut HashMap<u32, usize>,
    stats: &mut ConstraintStats,
) -> usize {
    match kind {
        Kind::Const => 0,
        Kind::Var => {
            stats.all_leaves.insert((variant, data));
            if matches!(variant, 2 | 3 | 4 | 5) {
                stats.column_leaves.insert((variant, data));
            }
            0
        }
        Kind::Expr => {
            // Recurse into the def.
            collect_recur(code, def_of, data, visited, stats)
        }
    }
}

fn collect_recur(
    code: &[Instruction32],
    def_of: &HashMap<u32, usize>,
    reg: u32,
    visited: &mut HashMap<u32, usize>,
    stats: &mut ConstraintStats,
) -> usize {
    if let Some(&d) = visited.get(&reg) {
        return d;
    }
    let idx = match def_of.get(&reg) {
        Some(&i) => i,
        None => {
            visited.insert(reg, 0);
            return 0;
        }
    };
    stats.op_count += 1;
    let instr = &code[idx];
    let op = Opcode::from(instr.opcode);
    let (b_kind, c_kind) = operand_kinds(op);
    let mut max_child = 0usize;
    if let Some(k) = b_kind {
        max_child = max_child.max(handle_operand(
            code,
            def_of,
            k,
            instr.b_variant,
            instr.b,
            visited,
            stats,
        ));
    }
    if let Some(k) = c_kind {
        max_child = max_child.max(handle_operand(
            code,
            def_of,
            k,
            instr.c_variant,
            instr.c,
            visited,
            stats,
        ));
    }
    let d = 1 + max_child;
    visited.insert(reg, d);
    d
}

#[derive(Copy, Clone)]
enum Kind {
    Const,
    Var,
    Expr,
}

fn operand_kinds(op: Opcode) -> (Option<Kind>, Option<Kind>) {
    use Kind::*;
    use Opcode::*;
    match op {
        Empty => (None, None),
        FAssertZero | EAssertZero => (Some(Expr), None),

        // Base-field
        FAssignC => (Some(Const), None),
        FAssignV => (Some(Var), None),
        FAssignE | FNegE | FAddAssignE | FSubAssignE | FMulAssignE => (Some(Expr), None),
        FAddVC | FSubVC | FMulVC => (Some(Var), Some(Const)),
        FAddVV | FSubVV | FMulVV => (Some(Var), Some(Var)),
        FAddVE | FSubVE | FMulVE => (Some(Var), Some(Expr)),
        FAddEC | FSubEC | FMulEC => (Some(Expr), Some(Const)),
        FAddEV | FSubEV | FMulEV => (Some(Expr), Some(Var)),
        FAddEE | FSubEE | FMulEE => (Some(Expr), Some(Expr)),

        // Extension-field
        EAssignC => (Some(Const), None),
        EAssignV => (Some(Var), None),
        EAssignE | ENegE | EAddAssignE | ESubAssignE | EMulAssignE => (Some(Expr), None),
        EAddVC | ESubVC | EMulVC => (Some(Var), Some(Const)),
        EAddVV | ESubVV | EMulVV => (Some(Var), Some(Var)),
        EAddVE | ESubVE | EMulVE => (Some(Var), Some(Expr)),
        EAddEC | ESubEC | EMulEC => (Some(Expr), Some(Const)),
        EAddEV | ESubEV | EMulEV => (Some(Expr), Some(Var)),
        EAddEE | ESubEE | EMulEE => (Some(Expr), Some(Expr)),

        // EF-mixed
        EFFromE => (Some(Expr), None),
        EFAddEE | EFSubEE | EFMulEE => (Some(Expr), Some(Expr)),
        EFAddAssignE | EFSubAssignE | EFMulAssignE => (Some(Expr), None),
        EFAsBaseSlice => (Some(Expr), None),
    }
}
