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
//! - Optionally writes a full lifted witness via `OUT_WITNESS=path` (u64-le, length = R1LF.num_vars)
#![allow(clippy::print_stdout)]

use std::collections::BTreeMap;
use std::io::Write;

use p3_baby_bear::BabyBear;
use p3_baby_bear::DiffusionMatrixBabyBear;
use p3_field::{AbstractField, PrimeField64};
use sp1_recursion_circuit::machine::SP1CompressWithVKeyWitnessValues;
use sp1_recursion_circuit::witness::Witnessable;
use sp1_recursion_circuit::BabyBearFriConfig;
use sp1_recursion_compiler::{
    config::InnerConfig,
    ir::{Builder, DslIr},
    r1cs::{
        lf::{lift_r1cs_to_lf_with_linear_carries, lift_r1cs_to_lf_with_linear_carries_and_witness},
        R1CSCompiler,
    },
};
use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;
use sp1_stark::BabyBearPoseidon2Inner;
use sp1_stark::StarkGenericConfig;

use sp1_prover::{CompressAir, InnerSC, ShrinkAir};
use sp1_core_executor::SP1Context;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::SP1Prover;
use sp1_stark::SP1ProverOpts;
use sp1_recursion_core::{Address, Runtime};
use sp1_recursion_compiler::circuit::AsmCompiler;
use sp1_recursion_compiler::ir::DslIrProgram;

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

fn write_u64le(path: &str, xs: &[u64]) {
    let mut f = std::fs::File::create(path).expect("create OUT_WITNESS");
    for &x in xs {
        f.write_all(&x.to_le_bytes()).expect("write witness");
    }
}

fn parse_mem_id(id: &str) -> Option<(u64, usize)> {
    if let Some(rest) = id.strip_prefix("felt") {
        let n: u64 = rest.parse().ok()?;
        return Some((n, 0));
    }
    if let Some(rest) = id.strip_prefix("var") {
        let n: u64 = rest.parse().ok()?;
        return Some((n, 0));
    }
    if let Some(rest) = id.strip_prefix("ptr") {
        let n: u64 = rest.parse().ok()?;
        return Some((n, 0));
    }
    if let Some(rest) = id.strip_prefix("ext") {
        let (a, limb) = rest.split_once("__")?;
        let n: u64 = a.parse().ok()?;
        let limb: usize = limb.parse().ok()?;
        return Some((n, limb));
    }
    None
}

fn load_default_fibonacci_elf_bytes() -> Vec<u8> {
    // Prefer the (already-built) fibonacci example ELF if present.
    //
    // This is the simplest "known-good public input" program to prove, rather than proving the zkVM itself.
    // Path is relative to `sp1/crates/prover` (this crate).
    let prover_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let examples_dir = prover_dir.join("../../examples");
    let elf_path = examples_dir.join(
        "target/elf-compilation/riscv32im-succinct-zkvm-elf/release/fibonacci-program",
    );

    if elf_path.exists() {
        return std::fs::read(&elf_path)
            .unwrap_or_else(|e| panic!("failed to read default fibonacci ELF at {}: {e}", elf_path.display()));
    }

    // If it doesn't exist (fresh checkout), build it once using the canonical examples build flow.
    // This triggers `examples/fibonacci/script/build.rs`, which runs `sp1_build::build_program("../program")`.
    let status = std::process::Command::new("cargo")
        .arg("build")
        .arg("-p")
        .arg("fibonacci-script")
        .arg("--release")
        .current_dir(&examples_dir)
        .status()
        .expect("failed to spawn `cargo build -p fibonacci-script --release` in sp1/examples");

    if !status.success() {
        panic!(
            "failed to build default fibonacci ELF (exit={status}).\n\
             Try running manually:\n\
               (cd sp1/examples && cargo build -p fibonacci-script --release)\n\
             Or set ELF_PATH=/path/to/your/program.elf"
        );
    }

    std::fs::read(&elf_path)
        .unwrap_or_else(|e| panic!("built fibonacci-script, but ELF still missing at {}: {e}", elf_path.display()))
}

fn build_real_input_with_merkle() -> (SP1Prover, SP1CompressWithVKeyWitnessValues<BabyBearPoseidon2>) {
    // Build a concrete compress proof (from a small dummy program) and produce the shrink-verifier
    // circuit input (vk+proof+merkle) so we can materialize a full witness.
    //
    // This is statement-time; shape-only exports should NOT depend on this.
    let elf_bytes: Vec<u8> = if let Ok(path) = std::env::var("ELF_PATH") {
        std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read ELF_PATH={path}: {e}"))
    } else {
        load_default_fibonacci_elf_bytes()
    };
    let prover: SP1Prover = SP1Prover::new();
    let opts = SP1ProverOpts::auto();
    let context = SP1Context::default();

    let (_, pk_d, program, vk) = prover.setup(&elf_bytes);
    let mut stdin = SP1Stdin::new();
    // The fibonacci example expects a `u32` input; default to something small and deterministic.
    let stdin_u32: u32 = std::env::var("ELF_STDIN_U32")
        .ok()
        .as_deref()
        .map(|s| s.parse().expect("failed to parse ELF_STDIN_U32 as u32"))
        .unwrap_or(10);
    stdin.write(&stdin_u32);
    let core_proof = prover.prove_core(&pk_d, program, &stdin, opts, context).unwrap();
    let compressed = prover.compress(&vk, core_proof, vec![], opts).unwrap();

    // The shrink verifier circuit verifies the *compressed* proof (vk+proof) with merkle proofs.
    let input = sp1_recursion_circuit::machine::SP1CompressWitnessValues {
        vks_and_proofs: vec![(compressed.vk.clone(), compressed.proof.clone())],
        is_complete: true,
    };
    let input_with_merkle = prover.make_merkle_proofs(input);
    (prover, input_with_merkle)
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

    // Build DslIr operations (shape-only by default).
    println!("Building shrink verifier circuit...");
    let maybe_input_with_merkle = if std::env::var("OUT_WITNESS").is_ok() {
        let (p, input) = build_real_input_with_merkle();
        drop(p);
        Some(input)
    } else {
        None
    };

    // If OUT_WITNESS is set, compile the circuit with a real input so we can also run the
    // recursion runtime and dump a full witness (including lift aux vars).
    let ops = if let Some(input_with_merkle) = maybe_input_with_merkle.as_ref() {
        let machine = ShrinkAir::shrink_machine(InnerSC::compressed());
        let mut builder = Builder::<InnerConfig>::default();
        let input = input_with_merkle.read(&mut builder);
        sp1_recursion_circuit::machine::SP1CompressRootVerifierWithVKey::verify(
            &mut builder,
            &machine,
            input,
            true, // enable value assertions for a concrete witness run
            sp1_recursion_circuit::machine::PublicValuesOutputDigest::Reduce,
        );
        builder.into_operations()
    } else {
        build_shrink_verifier_ops()
    };
    
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
        println!("\nLifting R1CS for LF+ (full lift: mul quotients + linear carries)...");
        let t_lift = std::time::Instant::now();
        let (r1lf, stats) = if let Ok(wit_path) = std::env::var("OUT_WITNESS") {
            // Build a full R1CS witness from recursion runtime memory, then lift+extend it.
            let input_with_merkle = maybe_input_with_merkle.as_ref().expect("input must exist");

            // Build the same block and execute it in recursion runtime to fill memory.
            let machine = ShrinkAir::shrink_machine(InnerSC::compressed());
            let mut builder = Builder::<InnerConfig>::default();
            let input = input_with_merkle.read(&mut builder);
            sp1_recursion_circuit::machine::SP1CompressRootVerifierWithVKey::verify(
                &mut builder,
                &machine,
                input,
                true,
                sp1_recursion_circuit::machine::PublicValuesOutputDigest::Reduce,
            );
            let block = builder.into_root_block();

            // Compile to recursion program.
            let dsl_program = unsafe { DslIrProgram::new_unchecked(block.clone()) };
            let mut asm = AsmCompiler::<InnerConfig>::default();
            let program = std::sync::Arc::new(asm.compile(dsl_program));

            type F = <InnerSC as StarkGenericConfig>::Val;
            type EF = <InnerSC as StarkGenericConfig>::Challenge;
            let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new(
                program.clone(),
                BabyBearPoseidon2Inner::new().perm,
            );
            let mut witness_stream = Vec::new();
            Witnessable::<InnerConfig>::write(input_with_merkle, &mut witness_stream);
            runtime.witness_stream = witness_stream.into();
            runtime.run().unwrap();

            // Compile to R1CS while retaining var_map.
            let mut c = R1CSCompiler::<InnerConfig>::new();
            for op in block.ops.clone() {
                c.compile_one(op);
            }
            c.r1cs.num_public = c.public_inputs.len();
            let r1cs2 = c.r1cs.clone();

            // Build full R1CS witness vector.
            let mut w_u64 = vec![0u64; r1cs2.num_vars];
            w_u64[0] = 1;
            // Fill constant vars: constraints of form 1 * const = var.
            for i in 0..r1cs2.num_constraints {
                let a = &r1cs2.a[i].terms;
                let b = &r1cs2.b[i].terms;
                let cc = &r1cs2.c[i].terms;
                if a.len() == 1 && a[0].0 == 0 && a[0].1 == BabyBear::one()
                    && b.len() == 1 && b[0].0 == 0
                    && cc.len() == 1 && cc[0].1 == BabyBear::one()
                    && cc[0].0 != 0
                {
                    w_u64[cc[0].0] = b[0].1.as_canonical_u64();
                }
            }
            // Fill DSL vars from runtime memory.
            for (id, idx) in c.var_map.iter() {
                let Some((addr_u64, limb)) = parse_mem_id(id.as_str()) else { continue };
                let addr = Address(BabyBear::from_canonical_u64(addr_u64));
                let entry = runtime.memory.mr(addr);
                let val = entry.val.0
                    .get(limb)
                    .copied()
                    .unwrap_or_else(|| BabyBear::zero());
                w_u64[*idx] = val.as_canonical_u64();
            }

            // Lift + compute aux witness.
            let w_bb: Vec<BabyBear> = w_u64.iter().map(|&x| BabyBear::from_canonical_u64(x)).collect();
            let (r1lf, stats, w_lf_u64) =
                lift_r1cs_to_lf_with_linear_carries_and_witness(&r1cs2, &w_bb)
                    .map_err(|e| format!("lift witness: {e}"))
                    .expect("lift_r1cs_to_lf_with_linear_carries_and_witness");

            // Write witness (single-file full witness for import).
            write_u64le(&wit_path, &w_lf_u64);
            println!("Wrote lifted witness to {wit_path} (len={})", w_lf_u64.len());

            (r1lf, stats)
        } else {
            // Shape-only lift (no witness).
            lift_r1cs_to_lf_with_linear_carries(&r1cs)
        };
        let elapsed_lift = t_lift.elapsed();
        r1lf.save_to_file(&path).expect("Failed to save R1LF");
        let file_size = std::fs::metadata(&path).unwrap().len();
        println!(
            "  lift done: {:?}  lifted={} skipped_bool={} skipped_eq={} skipped_select={} added_vars={} (q={} carry={})",
            elapsed_lift,
            stats.lifted_constraints,
            stats.skipped_bool,
            stats.skipped_eq,
            stats.skipped_select,
            stats.added_vars,
            stats.added_q_vars,
            stats.added_carry_vars
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
