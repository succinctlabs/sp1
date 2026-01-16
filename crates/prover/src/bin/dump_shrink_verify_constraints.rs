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
use p3_field::PrimeField64;
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
use sp1_core_machine::reduce::SP1ReduceProof;
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
    // this must match the Merkle tree height used by `SP1Prover::make_merkle_proofs`,
    // otherwise the shape-only R1CS (and its digest) will not match any real shrink-proof input
    // in configurations where the allowed VK set yields a height > 1.
    //
    // This is not "statement-time": the allowed VK set is embedded into the prover binary.
    let merkle_tree_height = SP1Prover::new().recursion_vk_tree.height;
    let shape = sp1_recursion_circuit::machine::SP1CompressWithVkeyShape {
        compress_shape: input_shape,
        merkle_tree_height,
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
        // keep this consistent with witness-mode export so the compiled R1CS shape
        // (num_vars/digest) matches between shape-only and witness-only runs.
        sp1_recursion_circuit::machine::PublicValuesOutputDigest::Reduce,
    );
    builder.into_operations()
}

fn read_r1lf_header(path: &str) -> Option<([u8; 32], u64, usize, usize, usize)> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut hdr = [0u8; 80];
    f.read_exact(&mut hdr).ok()?;
    if &hdr[0..4] != b"R1LF" {
        return None;
    }
    let version = u32::from_le_bytes(hdr[4..8].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hdr[8..40]);
    let p_bb = u64::from_le_bytes(hdr[40..48].try_into().ok()?);
    let num_vars = u64::from_le_bytes(hdr[48..56].try_into().ok()?) as usize;
    let num_constraints = u64::from_le_bytes(hdr[56..64].try_into().ok()?) as usize;
    let num_public = u64::from_le_bytes(hdr[64..72].try_into().ok()?) as usize;
    Some((digest, p_bb, num_vars, num_constraints, num_public))
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

fn eval_row_mod(
    row: &sp1_recursion_compiler::r1cs::types::SparseRow<BabyBear>,
    w: &[Option<u64>],
) -> u64 {
    let mut acc = 0u64;
    for (idx, coeff) in row.terms.iter() {
        let ci = coeff.as_canonical_u64();
        let wi = w[*idx].expect("witness slot missing during eval");
        acc = mod_add(acc, mod_mul(ci, wi));
    }
    acc
}
fn debug_first_unsatisfied_row(
    r1cs: &sp1_recursion_compiler::r1cs::types::R1CS<BabyBear>,
    w: &[Option<u64>],
    origin: &[u8],
    idx_to_id: &[Option<String>],
    max_rows: usize,
) -> Option<usize> {
    for i in 0..r1cs.num_constraints.min(max_rows) {
        let a = eval_row_mod(&r1cs.a[i], w);
        let b = eval_row_mod(&r1cs.b[i], w);
        let c = eval_row_mod(&r1cs.c[i], w);
        if mod_mul(a, b) != c {
            // Use stdout (not stderr) so logs capture it reliably.
            println!("\n[exporter debug] first unsatisfied row i={i} (within first {max_rows})");
            println!("  a={a} b={b} c={c} a*b-c mod p={}", (mod_mul(a, b) + BABYBEAR_P - c) % BABYBEAR_P);
            let dump_row = |name: &str, row: &sp1_recursion_compiler::r1cs::types::SparseRow<BabyBear>| {
                println!("  {name}: terms={}", row.terms.len());
                for (idx, coeff) in row.terms.iter().take(16) {
                    let wi = w[*idx].unwrap_or(u64::MAX);
                    let src = origin[*idx];
                    let id = idx_to_id.get(*idx).and_then(|x| x.as_ref()).map(|s| s.as_str()).unwrap_or("-");
                    println!("    idx={idx:<8} coeff={} wi={wi:<10} origin={src} id={id}", coeff.as_canonical_u64());
                }
                if row.terms.len() > 16 {
                    println!("    ... (truncated)");
                }
            };
            dump_row("A", &r1cs.a[i]);
            dump_row("B", &r1cs.b[i]);
            dump_row("C", &r1cs.c[i]);
            return Some(i);
        }
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

fn load_or_build_input_with_merkle(
) -> (SP1Prover, SP1CompressWithVKeyWitnessValues<BabyBearPoseidon2>) {
    // Cache the shrink proof (vk + proof) to avoid regenerating it between runs.
    //
    // - Set `SHRINK_PROOF_CACHE=/path/to/shrink_proof.bin` to enable caching.
    // - Set `REBUILD_SHRINK_PROOF=1` to force re-proving even if cache exists.
    //
    // This keeps the dumper fast while iterating on R1CS witness generation: we can reuse the same
    // proof and only redo the R1CS compile + satisfiability check.
    let cache_path = std::env::var("SHRINK_PROOF_CACHE").ok();
    let force_rebuild = std::env::var("REBUILD_SHRINK_PROOF").ok().as_deref() == Some("1");

    if let (Some(path), false) = (cache_path.as_deref(), force_rebuild) {
        if std::path::Path::new(path).exists() {
            let prover: SP1Prover = SP1Prover::new();
            let file = std::fs::File::open(path).expect("open SHRINK_PROOF_CACHE");
            let shrink: SP1ReduceProof<InnerSC> =
                bincode::deserialize_from(file).expect("deserialize SHRINK_PROOF_CACHE");

            let input = sp1_recursion_circuit::machine::SP1CompressWitnessValues {
                vks_and_proofs: vec![(shrink.vk.clone(), shrink.proof.clone())],
                is_complete: true,
            };
            let input_with_merkle = prover.make_merkle_proofs(input);
            println!("Loaded shrink proof from SHRINK_PROOF_CACHE={path}");
            return (prover, input_with_merkle);
        }
    }

    let (prover, input_with_merkle) = build_real_input_with_merkle();

    if let Some(path) = cache_path.as_deref() {
        // Persist vk+proof only (merkle proofs can be recomputed cheaply).
        let (vk, proof) = input_with_merkle
            .compress_val
            .vks_and_proofs
            .first()
            .expect("expected one shrink proof")
            .clone();
        let shrink = SP1ReduceProof::<InnerSC> { vk, proof };
        let file = std::fs::File::create(path).expect("create SHRINK_PROOF_CACHE");
        bincode::serialize_into(file, &shrink).expect("serialize SHRINK_PROOF_CACHE");
        println!("Cached shrink proof to SHRINK_PROOF_CACHE={path}");
    }

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
        let (p, input) = load_or_build_input_with_merkle();
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
            // keep algebraic shape identical to `build_shrink_verifier_ops()`.
            false,
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

    // Export modes:
    // - If OUT_WITNESS is set: dump witness, and (optionally) also write OUT_R1CS_LF if requested.
    // - Else if OUT_R1CS_LF is set: dump the (shape) R1LF ONLY.
    let out_r1lf = std::env::var("OUT_R1CS_LF").ok();
    let out_witness = std::env::var("OUT_WITNESS").ok();
    let mut r1cs_stats: Option<(usize, usize, usize, [u8; 32])> = None; // (num_vars, num_constraints, num_public, digest)

    // Compile to R1CS:
    // - In witness mode, we compile a var-map retaining R1CS later (r1cs2), so skip the early compile.
    // - In shape-only mode, compile once here from `ops`.
    let r1cs_shape_only = if out_witness.is_none() {
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
        r1cs_stats = Some((r1cs.num_vars, r1cs.num_constraints, r1cs.num_public, digest));
        println!("\n  R1CS Digest (SHA256):");
        println!("    {:02x?}", &digest[..16]);
        println!("    {:02x?}", &digest[16..]);
        Some(r1cs)
    } else {
        None
    };

    if let Some(wit_path) = out_witness.as_deref() {
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
                // Keep algebraic shape identical to `build_shrink_verifier_ops()`.
                false,
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
            let mut witness_blocks = Vec::new();
            Witnessable::<InnerConfig>::write(input_with_merkle, &mut witness_blocks);
            let witness_blocks_for_fill = witness_blocks.clone();
            runtime.witness_stream = witness_blocks.into();
            runtime.run().unwrap();

            // Compile to R1CS **and** generate the full witness in one pass.
            //
            // This is statement-bound and deterministic: values for internal temporaries allocated
            // during lowering (Poseidon2 expansion, ext-mul products, etc.) are computed from the
            // same semantics that emitted the constraints, rather than "solving" the finished R1CS.
            let hint_pos = std::cell::Cell::new(0usize);
            let mut next_hint_felt = || -> Option<BabyBear> {
                let pos = hint_pos.get();
                let blk = witness_blocks_for_fill.get(pos)?;
                hint_pos.set(pos + 1);
                Some(blk.0[0])
            };
            let mut next_hint_ext = || -> Option<[BabyBear; 4]> {
                let pos = hint_pos.get();
                let blk = witness_blocks_for_fill.get(pos)?;
                hint_pos.set(pos + 1);
                Some([blk.0[0], blk.0[1], blk.0[2], blk.0[3]])
            };
            let mut get_value = |id: &str| -> Option<BabyBear> {
                let (addr_u64, limb) = parse_mem_id(id)?;
                let vaddr: usize = addr_u64.try_into().ok()?;
                let &paddr = asm.virtual_to_physical.get(vaddr)?;
                let entry = runtime.memory.mr(paddr);
                entry.val.0.get(limb).copied()
            };

            let (c, w_bb) = R1CSCompiler::<InnerConfig>::compile_with_witness(
                block.ops.clone(),
                &mut get_value,
                &mut next_hint_felt,
                &mut next_hint_ext,
            );
            let r1cs2 = c.r1cs.clone();

            // Print R1CS stats/digest from this compilation (so witness mode still reports them).
            println!("\n=========================================================");
            println!("R1CS Compilation Complete (witness-mode, var_map-retaining)");
            println!("=========================================================");
            println!("  Variables:    {:>12}", r1cs2.num_vars);
            println!("  Constraints:  {:>12}", r1cs2.num_constraints);
            println!("  Public inputs:{:>12}", r1cs2.num_public);
            let digest = r1cs2.digest();
            r1cs_stats = Some((r1cs2.num_vars, r1cs2.num_constraints, r1cs2.num_public, digest));
            println!("\n  R1CS Digest (SHA256):");
            println!("    {:02x?}", &digest[..16]);
            println!("    {:02x?}", &digest[16..]);

            // Optional audit: detect unconstrained variables.
            if std::env::var("R1CS_AUDIT_UNCONSTRAINED").ok().as_deref() == Some("1") {
                let unconstrained_all = r1cs2.unconstrained_vars();
                let unconstrained_internal = c.unconstrained_internal_vars();
                let unconstrained_public: Vec<usize> = unconstrained_all
                    .iter()
                    .copied()
                    .filter(|&i| i >= 1 && i <= r1cs2.num_public)
                    .collect();
                println!("\n=========================================================");
                println!("R1CS Unconstrained Variable Audit");
                println!("=========================================================");
                println!(
                    "  unconstrained_total (excl idx0): {}",
                    unconstrained_all.len()
                );
                println!(
                    "  unconstrained_public (subset of 1..=num_public): {}",
                    unconstrained_public.len()
                );
                println!(
                    "  unconstrained_internal (excl explicit inputs): {}",
                    unconstrained_internal.len()
                );
                if !unconstrained_public.is_empty() {
                    let k = unconstrained_public.len().min(50);
                    println!(
                        "  first {} unconstrained_public indices: {:?}",
                        k,
                        &unconstrained_public[..k]
                    );
                    panic!("R1CS audit failed: found unconstrained public inputs");
                }
                if !unconstrained_internal.is_empty() {
                    let k = unconstrained_internal.len().min(50);
                    println!(
                        "  first {} unconstrained_internal indices: {:?}",
                        k,
                        &unconstrained_internal[..k]
                    );
                    panic!("R1CS audit failed: found unconstrained internal variables");
                }
            }

            // Sanity check: the compiler-produced witness must satisfy the R1CS exactly.
            if !r1cs2.is_satisfied(&w_bb) {
                let mut idx_to_id: Vec<Option<String>> = vec![None; r1cs2.num_vars];
                for (id, idx) in c.var_map.iter() {
                    if *idx < idx_to_id.len() {
                        idx_to_id[*idx] = Some(id.clone());
                    }
                }
                // Reuse existing debug helper (expects Option<u64>); adapt minimally here.
                let w_opt: Vec<Option<u64>> = w_bb.iter().map(|x| Some(x.as_canonical_u64())).collect();
                let origin: Vec<u8> = vec![3u8; r1cs2.num_vars];
                let max_rows: usize = std::env::var("DEBUG_MAX_ROWS")
                    .ok()
                    .as_deref()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(200_000);
                let found = debug_first_unsatisfied_row(&r1cs2, &w_opt, &origin, &idx_to_id, max_rows);
                if found.is_none() {
                    println!(
                        "[exporter debug] witness failed, but no unsatisfied row found within DEBUG_MAX_ROWS={} (total constraints={})",
                        max_rows, r1cs2.num_constraints
                    );
                }
                panic!("compiler-produced witness does not satisfy R1CS");
            }

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

        // If OUT_R1CS_LF is also set, reuse existing file if it matches; otherwise rewrite.
        if let Some(out_path) = out_r1lf.as_deref() {
            let want_digest = r1lf.digest();
            let want_p = r1lf.p_bb;
            let want_nv = r1lf.num_vars;
            let want_nc = r1lf.num_constraints;
            let want_np = r1lf.num_public;
            let mut should_write = true;
            if let Some((d, p, nv, nc, npub)) = read_r1lf_header(out_path) {
                if d == want_digest && p == want_p && nv == want_nv && nc == want_nc && npub == want_np {
                    should_write = false;
                    println!("OUT_R1CS_LF exists and matches witness-mode shape; skipping write: {out_path}");
                } else {
                    println!(
                        "OUT_R1CS_LF exists but does NOT match witness-mode shape; rewriting: {out_path}\n  have: num_vars={} num_constraints={} num_public={} p_bb={} digest={:02x?}...\n  want: num_vars={} num_constraints={} num_public={} p_bb={} digest={:02x?}...",
                        nv,
                        nc,
                        npub,
                        p,
                        &d[..8],
                        want_nv,
                        want_nc,
                        want_np,
                        want_p,
                        &want_digest[..8],
                    );
                }
            }
            if should_write {
                let t_save = std::time::Instant::now();
                r1lf.save_to_file(out_path).expect("Failed to save OUT_R1CS_LF");
                println!("Wrote R1LF to {out_path} in {:?}", t_save.elapsed());
            }
        }
    } else if let Some(path) = out_r1lf.as_deref() {
        println!("\nLifting R1CS for LF+ (shape mode: write R1LF only)...");
        let t_lift_total = std::time::Instant::now();
        let r1cs = r1cs_shape_only.expect("shape-only R1CS must have been compiled");
        let (r1lf, stats) = lift_r1cs_to_lf_with_linear_carries(&r1cs);
        let want_digest = r1lf.digest();
        let want_p = r1lf.p_bb;
        let want_nv = r1lf.num_vars;
        let want_nc = r1lf.num_constraints;
        let want_np = r1lf.num_public;
        let mut should_write = true;
        if let Some((d, p, nv, nc, npub)) = read_r1lf_header(path) {
            if d == want_digest && p == want_p && nv == want_nv && nc == want_nc && npub == want_np {
                should_write = false;
                println!("OUT_R1CS_LF exists and matches shape; skipping write: {path}");
            } else {
                println!(
                    "OUT_R1CS_LF exists but differs; rewriting: {path}\n  have: num_vars={} num_constraints={} num_public={} p_bb={} digest={:02x?}...\n  want: num_vars={} num_constraints={} num_public={} p_bb={} digest={:02x?}...",
                    nv,
                    nc,
                    npub,
                    p,
                    &d[..8],
                    want_nv,
                    want_nc,
                    want_np,
                    want_p,
                    &want_digest[..8],
                );
            }
        }
        let (dt_save, mbps, mb) = if should_write {
            let t_save = std::time::Instant::now();
            r1lf.save_to_file(path).expect("Failed to save R1LF");
            let dt_save = t_save.elapsed();
            let file_size = std::fs::metadata(path).unwrap().len();
            let mb = file_size as f64 / 1_000_000.0;
            let mbps = mb / dt_save.as_secs_f64().max(1e-9);
            (dt_save, mbps, mb)
        } else {
            let file_size = std::fs::metadata(path).unwrap().len();
            let mb = file_size as f64 / 1_000_000.0;
            (std::time::Duration::from_secs(0), 0.0, mb)
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
        if should_write {
            println!("  R1LF save time: {:?} ({:.2} MB/s)", dt_save, mbps);
        }
        println!(
            "  R1LF: num_vars={} num_constraints={} num_public={} digest={:02x?}...",
            r1lf.num_vars,
            r1lf.num_constraints,
            r1lf.num_public,
            &r1lf.digest()[..8]
        );
        if should_write {
            println!("Wrote R1LF to {path} ({:.2} MB)", mb);
        }
    }
    
    // Optionally write JSON stats (for quick inspection without loading full R1CS)
    if let Ok(path) = std::env::var("OUT_R1CS_JSON") {
        let (num_vars, num_constraints, num_public, digest) =
            r1cs_stats.expect("R1CS stats should be available before OUT_R1CS_JSON");
        let digest_hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        let stats = format!(
            "{{\"num_vars\":{},\"num_constraints\":{},\"num_public\":{},\"digest\":\"{}\"}}", 
            num_vars, 
            num_constraints, 
            num_public,
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
