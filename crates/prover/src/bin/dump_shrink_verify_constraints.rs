//! Compile the SP1 shrink verifier circuit to R1CS format.
//!
//! This builds the BabyBear-native STARK verifier relation (InnerConfig) and compiles it
//! to R1CS constraints for use with Symphony/lattice-based witness encryption.
//!
//! Run:
//!   cargo run -p sp1-prover --bin dump_shrink_verify_constraints --release
//!
//! Output:
//! - Prints R1CS statistics (variables, constraints, digest)
//! - Optionally writes LF-targeted lifted R1CS via `OUT_R1CS_LF=path`
#![allow(clippy::print_stdout)]

use std::collections::BTreeMap;

use p3_baby_bear::BabyBear;
use sp1_recursion_circuit::machine::SP1CompressWithVKeyWitnessValues;
use sp1_recursion_circuit::witness::Witnessable;
use sp1_recursion_circuit::BabyBearFriConfig;
use sp1_recursion_compiler::{
    config::InnerConfig,
    ir::{Builder, DslIr},
    r1cs::{lf::lift_r1cs_to_lf, R1CSCompiler},
};
use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;

use sp1_prover::{InnerSC, ShrinkAir};

/// Extract opcode tag from DslIr variant for histogram.
fn tag_of_instruction<C: sp1_recursion_compiler::ir::Config + core::fmt::Debug>(op: &DslIr<C>) -> String {
    let s = format!("{op:?}");
    let end = s
        .find(|ch: char| ch == '(' || ch == '{' || ch.is_whitespace())
        .unwrap_or(s.len());
    s[..end].to_string()
}

/// Recursively count opcodes including nested blocks.
fn visit_ops<C: sp1_recursion_compiler::ir::Config + core::fmt::Debug>(
    ops: &[DslIr<C>],
    counts: &mut BTreeMap<String, usize>,
) {
    for op in ops {
        *counts.entry(tag_of_instruction(op)).or_default() += 1;
        match op {
            DslIr::Parallel(blocks) => {
                for b in blocks {
                    visit_ops(&b.ops, counts);
                }
            }
            DslIr::For(b) => {
                let (_, _, _, _, body) = &**b;
                visit_ops(body, counts);
            }
            DslIr::IfEq(b) | DslIr::IfNe(b) => {
                let (_, _, then_body, else_body) = &**b;
                visit_ops(then_body, counts);
                visit_ops(else_body, counts);
            }
            DslIr::IfEqI(b) | DslIr::IfNeI(b) => {
                let (_, _, then_body, else_body) = &**b;
                visit_ops(then_body, counts);
                visit_ops(else_body, counts);
            }
            _ => {}
        }
    }
}

/// Build the shrink verifier DslIr operations.
fn build_shrink_verifier_ops() -> Vec<DslIr<InnerConfig>> {
    let machine = ShrinkAir::shrink_machine(InnerSC::compressed());
    let shrink_shape = ShrinkAir::<BabyBear>::shrink_shape().into();
    let input_shape = sp1_recursion_circuit::machine::SP1CompressShape::from(vec![shrink_shape]);
    let shape = sp1_recursion_circuit::machine::SP1CompressWithVkeyShape {
        compress_shape: input_shape,
        merkle_tree_height: 1,
    };
    let dummy_input: SP1CompressWithVKeyWitnessValues<BabyBearPoseidon2> =
        SP1CompressWithVKeyWitnessValues::dummy(&machine, &shape);

    let mut builder = Builder::<InnerConfig>::default();
    let input = dummy_input.read(&mut builder);
    sp1_recursion_circuit::machine::SP1CompressRootVerifierWithVKey::verify(
        &mut builder,
        &machine,
        input,
        false, // value_assertions disabled - we want algebraic shape only
        sp1_recursion_circuit::machine::PublicValuesOutputDigest::Root,
    );
    builder.into_operations()
}

fn main() {
    println!("=========================================================");
    println!("SP1 Shrink Verifier → R1CS Compilation");
    println!("=========================================================\n");

    // Print FRI config for reference
    let machine = ShrinkAir::shrink_machine(InnerSC::compressed());
    let fri = machine.config().fri_config();
    println!("FRI config:");
    println!("  log_blowup: {}", fri.log_blowup);
    println!("  num_queries: {}", fri.num_queries);
    println!("  proof_of_work_bits: {}", fri.proof_of_work_bits);
    println!(
        "  heuristic bits: {}",
        fri.num_queries.saturating_mul(fri.log_blowup) + fri.proof_of_work_bits
    );
    println!();

    // Build DslIr operations
    println!("Building shrink verifier circuit...");
    let ops = build_shrink_verifier_ops();
    
    // Print opcode histogram
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    visit_ops(&ops, &mut counts);
    let mut counts_sorted: Vec<_> = counts.iter().collect();
    counts_sorted.sort_by(|(a, an), (b, bn)| bn.cmp(an).then_with(|| a.cmp(b)));
    
    println!("\nOpcode histogram (top 15):");
    for (op, n) in counts_sorted.iter().take(15) {
        println!("  {op:35} {n:>8}");
    }
    println!("  ... ({} total opcode types)", counts_sorted.len());
    println!("  Total ops: {}", ops.len());

    // Compile to R1CS
    println!("\nCompiling to R1CS...");
    let start = std::time::Instant::now();
    let r1cs = R1CSCompiler::<InnerConfig>::compile(ops);
    let elapsed = start.elapsed();

    println!("\n=========================================================");
    println!("R1CS Compilation Complete");
    println!("=========================================================");
    println!("  Variables:    {:>12}", r1cs.num_vars);
    println!("  Constraints:  {:>12}", r1cs.num_constraints);
    println!("  Public inputs:{:>12}", r1cs.num_public);
    println!("  Compile time: {:>12.2?}", elapsed);
    
    // Compute and print digest
    let digest = r1cs.digest();
    println!("\n  R1CS Digest (SHA256):");
    println!("    {:02x?}", &digest[..16]);
    println!("    {:02x?}", &digest[16..]);

    // Optionally write LF-targeted lifted R1CS (integer coefficients + selective lifting).
    if let Ok(path) = std::env::var("OUT_R1CS_LF") {
        println!("\nLifting R1CS for LF+ (selective lift + integer coeffs)...");
        let t_lift = std::time::Instant::now();
        let (r1lf, stats) = lift_r1cs_to_lf(&r1cs);
        let elapsed_lift = t_lift.elapsed();
        r1lf.save_to_file(&path).expect("Failed to save R1LF");
        let file_size = std::fs::metadata(&path).unwrap().len();
        println!(
            "  lift done: {:?}  lifted={} skipped_bool={} skipped_eq={} skipped_select={} added_vars={}",
            elapsed_lift,
            stats.lifted_constraints,
            stats.skipped_bool,
            stats.skipped_eq,
            stats.skipped_select,
            stats.added_vars
        );
        println!(
            "  R1LF: num_vars={} num_constraints={} num_public={} digest={:02x?}...",
            r1lf.num_vars,
            r1lf.num_constraints,
            r1lf.num_public,
            &r1lf.digest()[..8]
        );
        println!("Wrote R1LF to {path} ({:.2} MB)", file_size as f64 / 1_000_000.0);
    }
    
    // Optionally write JSON stats (for quick inspection without loading full R1CS)
    if let Ok(path) = std::env::var("OUT_R1CS_JSON") {
        let digest_hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        let stats = format!(
            "{{\"num_vars\":{},\"num_constraints\":{},\"num_public\":{},\"digest\":\"{}\"}}", 
            r1cs.num_vars, 
            r1cs.num_constraints, 
            r1cs.num_public,
            digest_hex
        );
        std::fs::write(&path, stats).unwrap();
        println!("Wrote R1CS stats to {path}");
    }

    if std::env::var("OUT_R1CS_LF").is_err() {
        println!("\nSet OUT_R1CS_LF=/path/to/shrink_verifier.r1lf to write the LF-targeted format.");
    }
}

/// Integration tests for R1CS compilation of the shrink verifier.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shrink_verifier_r1cs_compilation() {
        let ops = build_shrink_verifier_ops();
        
        // Print opcode histogram
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        visit_ops(&ops, &mut counts);
        println!("Shrink verifier: {} opcode types, {} total ops", counts.len(), ops.len());

        // Compile to R1CS
        let r1cs = R1CSCompiler::<InnerConfig>::compile(ops.clone());

        assert!(r1cs.num_constraints > 0, "Should have generated constraints");
        assert!(r1cs.num_vars > 100, "Should have allocated many variables");

        println!("R1CS: {} vars, {} constraints", r1cs.num_vars, r1cs.num_constraints);
        
        // Verify determinism
        let r1cs2 = R1CSCompiler::<InnerConfig>::compile(ops);
        assert_eq!(r1cs.num_vars, r1cs2.num_vars);
        assert_eq!(r1cs.num_constraints, r1cs2.num_constraints);
        assert_eq!(r1cs.digest(), r1cs2.digest());
        
        println!("Determinism verified ✓");
    }
}
