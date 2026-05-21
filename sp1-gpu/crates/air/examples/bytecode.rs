//! Smoke test for the v2 bytecode lowering.
//!
//! Builds DAG → analyzes → chunks → enumerates lowerings → lowers each
//! Sequential plan to bytecode. Prints per-chunk bytecode stats so we can
//! eyeball that the lowering's working correctly.

use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_air::ir::{
    analyze_constraints, build_dag, chunk_dag, enumerate_lowerings, lower_sequential, BcOp,
    ChunkBudget, Lowering,
};
use sp1_gpu_air::F;
use sp1_hypercube::air::MachineAir;

const FOCUS: &[&str] = &["Add", "Bitwise", "Mul", "Branch", "KeccakPermute"];

fn main() {
    let machine = RiscvAir::<F>::machine();
    let budget = ChunkBudget::recommended();

    println!(
        "{:<22} {:>5} {:>6} {:>5} {:>5} {:>5} {:>5} {:>5} {:>8}",
        "chip", "nChnk", "instrs", "leaf", "const", "pub", "asrt", "maxR", "compat?"
    );
    println!("{}", "-".repeat(78));

    for chip in machine.chips() {
        let name = chip.name();
        if !FOCUS.contains(&name) {
            continue;
        }
        let dag = build_dag(chip.air.as_ref());
        let infos = analyze_constraints(&dag);
        let chunks = chunk_dag(&infos, &budget);

        let mut total = LoweredStats::default();
        for chunk in &chunks {
            let lowerings = enumerate_lowerings(chunk, &infos, &dag);
            let plan = lowerings
                .iter()
                .find_map(|l| match l {
                    Lowering::Sequential(p) => Some(p),
                    _ => None,
                })
                .unwrap();
            let bc = lower_sequential(chunk, &infos, &dag, plan);
            total.add(&bc);
            // Sanity assertions:
            assert_eq!(bc.n_constraints, chunk.constraint_indices.len() as u32);
            assert!(bc.max_reg as usize <= plan.topo_order.len());
            // Every assertion's reg index must be inside `max_reg`.
            for &(reg, _) in &bc.asserts {
                assert!(reg < bc.max_reg, "assert reg {} >= max_reg {}", reg, bc.max_reg);
            }
        }
        println!(
            "{:<22} {:>5} {:>6} {:>5} {:>5} {:>5} {:>5} {:>5} {:>8}",
            name,
            chunks.len(),
            total.instrs,
            total.leaves,
            total.consts,
            total.publics,
            total.asserts,
            total.max_reg_seen,
            if total.all_compatible { "yes" } else { "MIXED" },
        );
    }

    println!("\nOpcode distribution across all chunks (KeccakPermute):");
    for chip in machine.chips() {
        if chip.name() != "KeccakPermute" {
            continue;
        }
        let dag = build_dag(chip.air.as_ref());
        let infos = analyze_constraints(&dag);
        let chunks = chunk_dag(&infos, &budget);
        let mut counts = [0u64; 8];
        for chunk in &chunks {
            let lowerings = enumerate_lowerings(chunk, &infos, &dag);
            let plan = lowerings
                .iter()
                .find_map(|l| match l {
                    Lowering::Sequential(p) => Some(p),
                    _ => None,
                })
                .unwrap();
            let bc = lower_sequential(chunk, &infos, &dag, plan);
            for instr in &bc.instrs {
                counts[instr.opcode as usize] += 1;
            }
        }
        let names =
            ["LoadLeaf", "LoadConst", "LoadPublic", "AddF", "SubF", "MulF", "NegF", "AssertF"];
        for (op, &n) in names.iter().zip(counts.iter()) {
            if n > 0 {
                println!("  {:<12} {}", op, n);
            }
        }
        break;
    }
}

#[derive(Default)]
struct LoweredStats {
    instrs: usize,
    leaves: usize,
    consts: usize,
    publics: usize,
    asserts: usize,
    max_reg_seen: u16,
    all_compatible: bool,
}

impl LoweredStats {
    fn add(&mut self, bc: &sp1_gpu_air::ir::ChunkBytecode) {
        self.instrs += bc.instrs.len();
        self.leaves += bc.leaves.len();
        self.consts += bc.consts.len();
        self.publics += bc.publics.len();
        self.asserts += bc.asserts.len();
        self.max_reg_seen = self.max_reg_seen.max(bc.max_reg);
        self.all_compatible = bc.is_compatible_with_v1_kernel() || self.all_compatible;
    }
}

// Suppress unused-import warning for BcOp (used in opcode-array indexing).
const _: fn() = || {
    let _ = BcOp::LoadLeaf;
};
