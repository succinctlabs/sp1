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

use sp1_prover::{InnerSC, ShrinkAir};
use sp1_core_executor::SP1Context;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::SP1Prover;
use sp1_stark::SP1ProverOpts;
use sp1_recursion_core::Runtime;
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
    // We want the *shrink-proof verifier* circuit: i.e. verify a proof produced by `prover.shrink(..)`.
    // Therefore the machine passed into the verifier is the *shrink machine config*.
    let machine_verified = ShrinkAir::shrink_machine(InnerSC::compressed());
    let shrink_shape = ShrinkAir::<BabyBear>::shrink_shape().into();
    let input_shape = sp1_recursion_circuit::machine::SP1CompressShape::from(vec![shrink_shape]);
    let shape = sp1_recursion_circuit::machine::SP1CompressWithVkeyShape {
        compress_shape: input_shape,
        merkle_tree_height: 1,
    };
    let dummy_input: SP1CompressWithVKeyWitnessValues<BabyBearPoseidon2> =
        SP1CompressWithVKeyWitnessValues::dummy(&machine_verified, &shape);

    let mut builder = Builder::<InnerConfig>::default();
    let input = dummy_input.read(&mut builder);
    sp1_recursion_circuit::machine::SP1CompressRootVerifierWithVKey::verify(
        &mut builder,
        &machine_verified,
        input,
        false, // value_assertions disabled - we want algebraic shape only
        sp1_recursion_circuit::machine::PublicValuesOutputDigest::Root,
    );
    builder.into_operations()
}

fn write_u64le(path: &str, xs: &[u64]) {
    let file = std::fs::File::create(path).expect("create OUT_WITNESS");
    let mut w = std::io::BufWriter::with_capacity(256 * 1024 * 1024, file);
    // Write in moderately large chunks to avoid per-u64 syscall overhead.
    let mut buf = vec![0u8; 8 * 1024 * 1024]; // 8MB
    let mut i = 0usize;
    while i < xs.len() {
        let take = ((buf.len() / 8).min(xs.len() - i)) as usize;
        for j in 0..take {
            let off = j * 8;
            buf[off..off + 8].copy_from_slice(&xs[i + j].to_le_bytes());
        }
        w.write_all(&buf[..take * 8]).expect("write witness chunk");
        i += take;
    }
    w.flush().expect("flush witness");
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

const BABYBEAR_P: u64 = 2013265921;

#[inline]
fn mod_add(a: u64, b: u64) -> u64 {
    let s = a + b;
    if s >= BABYBEAR_P { s - BABYBEAR_P } else { s }
}

#[inline]
fn mod_mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % (BABYBEAR_P as u128)) as u64
}

#[inline]
fn mod_inv(a: u64) -> Option<u64> {
    if a == 0 {
        return None;
    }
    // Fermat inverse: a^(p-2) mod p, p fits u64.
    let mut base = a;
    let mut exp = BABYBEAR_P - 2;
    let mut acc = 1u64;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = mod_mul(acc, base);
        }
        base = mod_mul(base, base);
        exp >>= 1;
    }
    Some(acc)
}

fn row_known_sum_and_single_unknown(
    row: &sp1_recursion_compiler::r1cs::types::SparseRow<BabyBear>,
    w: &[Option<u64>],
) -> (u64, Option<(usize, u64)>, usize) {
    let mut known_sum = 0u64;
    let mut unknown: Option<(usize, u64)> = None;
    let mut unknown_count = 0usize;
    for (idx, coeff) in row.terms.iter() {
        let ci = coeff.as_canonical_u64();
        match w.get(*idx).and_then(|x| *x) {
            Some(wi) => {
                known_sum = mod_add(known_sum, mod_mul(ci, wi));
            }
            None => {
                unknown_count += 1;
                if unknown_count == 1 {
                    unknown = Some((*idx, ci));
                }
            }
        }
    }
    (known_sum, unknown, unknown_count)
}

fn complete_witness_from_constraints(
    r1cs: &sp1_recursion_compiler::r1cs::types::R1CS<BabyBear>,
    w: &mut [Option<u64>],
) -> Result<(), String> {
    // Do a few propagation passes. We solve any constraint where exactly one witness slot is
    // unknown and all other terms in the constraint are known.
    //
    // Constraint: (A·w) * (B·w) = (C·w)  over BabyBear mod p.
    // If exactly one variable is unknown in one of the rows, we can solve it (when needed inverses exist).
    for _pass in 0..6 {
        let mut progress = 0usize;
        for i in 0..r1cs.num_constraints {
            let a = &r1cs.a[i];
            let b = &r1cs.b[i];
            let c = &r1cs.c[i];

            // Fast path: compute row metadata.
            let (a_known, a_unk, a_unk_cnt) = row_known_sum_and_single_unknown(a, w);
            let (b_known, b_unk, b_unk_cnt) = row_known_sum_and_single_unknown(b, w);
            let (c_known, c_unk, c_unk_cnt) = row_known_sum_and_single_unknown(c, w);

            // If exactly one unknown overall, solve it.
            let total_unknown = a_unk_cnt + b_unk_cnt + c_unk_cnt;
            if total_unknown != 1 {
                continue;
            }

            // Solve unknown in C row:
            if c_unk_cnt == 1 {
                let (dst, coeff) = c_unk.expect("c_unk");
                if dst != 0 && w[dst].is_none() {
                    // Need A and B fully known.
                    if a_unk_cnt == 0 && b_unk_cnt == 0 {
                        let target = mod_mul(a_known, b_known);
                        if let Some(inv_coeff) = mod_inv(coeff) {
                            // coeff*dst + c_known = target  => dst = (target - c_known)/coeff
                            let rhs = (target + BABYBEAR_P - c_known) % BABYBEAR_P;
                            w[dst] = Some(mod_mul(rhs, inv_coeff));
                            progress += 1;
                            continue;
                        }
                    }
                }
            }

            // Solve unknown in A row:
            if a_unk_cnt == 1 {
                let (dst, coeff) = a_unk.expect("a_unk");
                if dst != 0 && w[dst].is_none() {
                    if b_unk_cnt == 0 && c_unk_cnt == 0 {
                        // (a_known + coeff*dst) * b_known = c_known
                        // => a_known + coeff*dst = c_known / b_known
                        if let Some(inv_b) = mod_inv(b_known) {
                            let target_a = mod_mul(c_known, inv_b);
                            if let Some(inv_coeff) = mod_inv(coeff) {
                                let rhs = (target_a + BABYBEAR_P - a_known) % BABYBEAR_P;
                                w[dst] = Some(mod_mul(rhs, inv_coeff));
                                progress += 1;
                                continue;
                            }
                        }
                    }
                }
            }

            // Solve unknown in B row:
            if b_unk_cnt == 1 {
                let (dst, coeff) = b_unk.expect("b_unk");
                if dst != 0 && w[dst].is_none() {
                    if a_unk_cnt == 0 && c_unk_cnt == 0 {
                        if let Some(inv_a) = mod_inv(a_known) {
                            let target_b = mod_mul(c_known, inv_a);
                            if let Some(inv_coeff) = mod_inv(coeff) {
                                let rhs = (target_b + BABYBEAR_P - b_known) % BABYBEAR_P;
                                w[dst] = Some(mod_mul(rhs, inv_coeff));
                                progress += 1;
                                continue;
                            }
                        }
                    }
                }
            }
        }
        if progress == 0 {
            break;
        }
    }

    let missing = w.iter().skip(1).filter(|x| x.is_none()).count();
    if missing != 0 {
        let mut examples = Vec::new();
        for (i, v) in w.iter().enumerate().skip(1) {
            if v.is_none() {
                examples.push(i);
                if examples.len() >= 8 {
                    break;
                }
            }
        }
        return Err(format!(
            "could not complete witness: {missing} variables remain unset (examples: {:?})",
            examples
        ));
    }
    Ok(())
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
    // Build a concrete *shrink proof* (from a small example program) and produce the
    // shrink-proof-verifier circuit input (vk+proof+merkle) so we can materialize a full witness.
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
    let shrink = prover.shrink(compressed, opts).unwrap();

    // The shrink-proof verifier circuit verifies the *shrink* proof (vk+proof) with merkle proofs.
    let input = sp1_recursion_circuit::machine::SP1CompressWitnessValues {
        vks_and_proofs: vec![(shrink.vk.clone(), shrink.proof.clone())],
        is_complete: true,
    };
    let input_with_merkle = prover.make_merkle_proofs(input);
    (prover, input_with_merkle)
}

fn main() {
    println!("=========================================================");
    println!("SP1 Shrink Verifier → R1CS Compilation");
    println!("=========================================================\n");

    // Print FRI config for reference: this is the config of the *shrink proof* being verified.
    let machine_verified = ShrinkAir::shrink_machine(InnerSC::compressed());
    let fri = machine_verified.config().fri_config();
    println!("FRI config (verified shrink-proof machine):");
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
        let machine_verified = ShrinkAir::shrink_machine(InnerSC::compressed());
        let mut builder = Builder::<InnerConfig>::default();
        let input = input_with_merkle.read(&mut builder);
        sp1_recursion_circuit::machine::SP1CompressRootVerifierWithVKey::verify(
            &mut builder,
            &machine_verified,
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

    // Export modes:
    // - If OUT_WITNESS is set: dump witness ONLY (do not rewrite/write the R1LF shape every time).
    // - Else if OUT_R1CS_LF is set: dump the (shape) R1LF ONLY.
    let out_r1lf = std::env::var("OUT_R1CS_LF").ok();
    let out_witness = std::env::var("OUT_WITNESS").ok();

    if let Some(wit_path) = out_witness.as_deref() {
        if out_r1lf.is_some() {
            println!("NOTE: OUT_WITNESS is set, so we will NOT write OUT_R1CS_LF (shape export).");
        }
        println!("\nLifting R1CS for LF+ (witness mode: compute+dump witness only)...");
        let t_lift_total = std::time::Instant::now();

        let (r1lf, stats) = {
            // Build a full R1CS witness from recursion runtime memory, then lift+extend it.
            let input_with_merkle = maybe_input_with_merkle.as_ref().expect("input must exist");

            // Build the same block and execute it in recursion runtime to fill memory.
            let machine_verified = ShrinkAir::shrink_machine(InnerSC::compressed());
            let mut builder = Builder::<InnerConfig>::default();
            let input = input_with_merkle.read(&mut builder);
            sp1_recursion_circuit::machine::SP1CompressRootVerifierWithVKey::verify(
                &mut builder,
                &machine_verified,
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
            let mut w_opt: Vec<Option<u64>> = vec![None; r1cs2.num_vars];
            w_opt[0] = Some(1);
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
                    w_opt[cc[0].0] = Some(b[0].1.as_canonical_u64());
                }
            }
            // Fill DSL vars from runtime memory.
            for (id, idx) in c.var_map.iter() {
                let Some((addr_u64, limb)) = parse_mem_id(id.as_str()) else { continue };
                let vaddr: usize = addr_u64
                    .try_into()
                    .map_err(|_| format!("vaddr too large in id={id}"))
                    .expect("parse vaddr");
                let Some(&paddr) = asm.virtual_to_physical.get(vaddr) else {
                    // Some compiler-introduced IDs may not correspond to runtime memory.
                    // Those will be filled by constraint propagation below.
                    continue;
                };
                let entry = runtime.memory.mr(paddr);
                let val = entry.val.0
                    .get(limb)
                    .copied()
                    .unwrap_or_else(|| BabyBear::zero());
                w_opt[*idx] = Some(val.as_canonical_u64());
            }

            // Lift + compute aux witness.
            complete_witness_from_constraints(&r1cs2, &mut w_opt)
                .map_err(|e| format!("complete witness: {e}"))
                .expect("complete witness");
            let w_bb: Vec<BabyBear> = w_opt
                .into_iter()
                .map(|x| BabyBear::from_canonical_u64(x.expect("witness slot missing")))
                .collect();
            let t_aux = std::time::Instant::now();
            let (r1lf, stats, w_lf_u64) =
                lift_r1cs_to_lf_with_linear_carries_and_witness(&r1cs2, &w_bb)
                    .map_err(|e| format!("lift witness: {e}"))
                    .expect("lift_r1cs_to_lf_with_linear_carries_and_witness");
            let dt_aux = t_aux.elapsed();

            // Write witness (single-file full witness for import).
            let t_wit = std::time::Instant::now();
            write_u64le(&wit_path, &w_lf_u64);
            let dt_wit = t_wit.elapsed();
            let bytes = (w_lf_u64.len() as u64) * 8;
            let mb = bytes as f64 / 1_000_000.0;
            let mbps = mb / dt_wit.as_secs_f64().max(1e-9);
            println!(
                "Wrote lifted witness to {wit_path} (len={}, {:.2} MB) in {:?} ({:.2} MB/s)",
                w_lf_u64.len(),
                mb,
                dt_wit,
                mbps
            );
            println!("  lift+aux compute time (excluding write): {:?}", dt_aux);

            (r1lf, stats)
        };
        println!(
            "  lift done (total): {:?}  lifted={} skipped_bool={} skipped_eq={} skipped_select={} added_vars={} (q={} carry={})",
            t_lift_total.elapsed(),
            stats.lifted_constraints,
            stats.skipped_bool,
            stats.skipped_eq,
            stats.skipped_select,
            stats.added_vars,
            stats.added_q_vars,
            stats.added_carry_vars
        );
        println!(
            "  R1LF (in-memory): num_vars={} num_constraints={} num_public={} digest={:02x?}...",
            r1lf.num_vars,
            r1lf.num_constraints,
            r1lf.num_public,
            &r1lf.digest()[..8]
        );
    } else if let Some(path) = out_r1lf.as_deref() {
        println!("\nLifting R1CS for LF+ (shape mode: write R1LF only)...");
        let t_lift_total = std::time::Instant::now();
        let (r1lf, stats) = lift_r1cs_to_lf_with_linear_carries(&r1cs);
        let t_save = std::time::Instant::now();
        r1lf.save_to_file(path).expect("Failed to save R1LF");
        let dt_save = t_save.elapsed();
        let file_size = std::fs::metadata(path).unwrap().len();
        let mb = file_size as f64 / 1_000_000.0;
        let mbps = mb / dt_save.as_secs_f64().max(1e-9);
        println!(
            "  lift done (total): {:?}  lifted={} skipped_bool={} skipped_eq={} skipped_select={} added_vars={} (q={} carry={})",
            t_lift_total.elapsed(),
            stats.lifted_constraints,
            stats.skipped_bool,
            stats.skipped_eq,
            stats.skipped_select,
            stats.added_vars,
            stats.added_q_vars,
            stats.added_carry_vars
        );
        println!("  R1LF save time: {:?} ({:.2} MB/s)", dt_save, mbps);
        println!(
            "  R1LF: num_vars={} num_constraints={} num_public={} digest={:02x?}...",
            r1lf.num_vars,
            r1lf.num_constraints,
            r1lf.num_public,
            &r1lf.digest()[..8]
        );
        println!("Wrote R1LF to {path} ({:.2} MB)", mb);
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

    if out_witness.is_none() && out_r1lf.is_none() {
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
