//! Smoke test for the v2 DAG-native builder.
//!
//! Runs `build_dag` on a few chips, prints node/constraint counts and shows
//! cross-constraint sharing. Sanity check before further phases.

use std::collections::HashSet;

use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_air::v2::{build_dag, ConstraintDag, DagNode, NodeId, TraceSource};
use sp1_gpu_air::F;
use sp1_hypercube::air::MachineAir;

fn main() {
    let machine = RiscvAir::<F>::machine();

    let focus: &[&str] = &["Add", "Bitwise", "Mul", "Branch", "KeccakPermute"];

    println!(
        "{:<22} {:>5} {:>5} {:>6} {:>6} {:>7} {:>7} {:>9}",
        "chip", "main", "prep", "nodes", "cons", "leaves", "shared", "leafShar"
    );
    println!("{}", "-".repeat(78));

    for chip in machine.chips() {
        let name = chip.name();
        if !focus.iter().any(|f| name == *f) {
            continue;
        }
        let dag = build_dag(chip.air.as_ref());
        print_summary(name, &dag);
    }

    println!("\nDetailed leaf-share check (KeccakPermute):");
    for chip in machine.chips() {
        if chip.name() == "KeccakPermute" {
            let dag = build_dag(chip.air.as_ref());
            print_sharing_details(&dag);
            break;
        }
    }
}

fn print_summary(name: &str, dag: &ConstraintDag) {
    let leaves: HashSet<NodeId> = dag
        .nodes
        .iter()
        .enumerate()
        .filter_map(|(i, n)| match n {
            DagNode::InputLeaf { .. } => Some(i as NodeId),
            _ => None,
        })
        .collect();
    // For each leaf, count how many parent edges point at it.
    let mut leaf_uses: std::collections::HashMap<NodeId, u32> =
        leaves.iter().map(|&l| (l, 0u32)).collect();
    for n in &dag.nodes {
        for c in children(n) {
            if let Some(count) = leaf_uses.get_mut(&c) {
                *count += 1;
            }
        }
    }
    // Constraints also reference leaves through their roots; root → leaf walks happen below.
    let shared_leaves = leaf_uses.values().filter(|&&c| c > 1).count();
    let mean_uses = if leaf_uses.is_empty() {
        0.0
    } else {
        leaf_uses.values().sum::<u32>() as f64 / leaf_uses.len() as f64
    };

    println!(
        "{:<22} {:>5} {:>5} {:>6} {:>6} {:>7} {:>7} {:>9.2}",
        name,
        dag.main_width,
        dag.preprocessed_width,
        dag.nodes.len(),
        dag.constraints.len(),
        leaves.len(),
        shared_leaves,
        mean_uses,
    );
}

fn children(node: &DagNode) -> Vec<NodeId> {
    match *node {
        DagNode::InputLeaf { .. }
        | DagNode::PublicValue { .. }
        | DagNode::GlobalCumulativeSum { .. }
        | DagNode::ConstF { .. }
        | DagNode::ConstEF { .. }
        | DagNode::IsFirstRow
        | DagNode::IsLastRow
        | DagNode::IsTransition => vec![],
        DagNode::AddF { a, b }
        | DagNode::SubF { a, b }
        | DagNode::MulF { a, b }
        | DagNode::AddEF { a, b }
        | DagNode::SubEF { a, b }
        | DagNode::MulEF { a, b }
        | DagNode::EFAddF { a, b }
        | DagNode::EFSubF { a, b }
        | DagNode::EFMulF { a, b } => vec![a, b],
        DagNode::NegF { a } | DagNode::NegEF { a } | DagNode::EFFromF { a } => vec![a],
    }
}

fn print_sharing_details(dag: &ConstraintDag) {
    // Walk back from each constraint root and collect transitive column leaves.
    // Compare per-constraint leaf set sizes with the SSA-tape result from v1.
    let mut per_constraint_main: Vec<HashSet<u32>> = Vec::new();
    for c in &dag.constraints {
        let mut visited = HashSet::new();
        let mut main_cols = HashSet::new();
        collect_main_columns(&dag.nodes, c.root, &mut visited, &mut main_cols);
        per_constraint_main.push(main_cols);
    }
    let max_main = per_constraint_main.iter().map(|s| s.len()).max().unwrap_or(0);
    let mean_main = if per_constraint_main.is_empty() {
        0.0
    } else {
        per_constraint_main.iter().map(|s| s.len()).sum::<usize>() as f64
            / per_constraint_main.len() as f64
    };
    let union_main: HashSet<u32> = per_constraint_main.iter().flatten().copied().collect();
    let sum_main: usize = per_constraint_main.iter().map(|s| s.len()).sum();

    println!("  per-constraint MainLocal leaf counts: max={}  mean={:.1}", max_main, mean_main);
    println!("  union(MainLocal) across all constraints: {}", union_main.len());
    println!(
        "  overlap factor (sum/union): {:.2}x  (compare with v1 analyze_chips ≈ 6.0x)",
        sum_main as f64 / union_main.len().max(1) as f64
    );
}

fn collect_main_columns(
    nodes: &[DagNode],
    root: NodeId,
    visited: &mut HashSet<NodeId>,
    main_cols: &mut HashSet<u32>,
) {
    if !visited.insert(root) {
        return;
    }
    let node = &nodes[root as usize];
    if let DagNode::InputLeaf { source: TraceSource::MainLocal, col }
    | DagNode::InputLeaf { source: TraceSource::MainNext, col } = node
    {
        main_cols.insert(*col);
    }
    for c in children(node) {
        collect_main_columns(nodes, c, visited, main_cols);
    }
}
