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
//! - Optionally writes LF-targeted lifted R1CS via `SP1_R1LF=path`
//! - Optionally writes a **bundle** via `SP1_WITNESS=path` (witness + public inputs)
#![allow(clippy::print_stdout)]

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::io::Write;

use p3_baby_bear::BabyBear;
use p3_baby_bear::DiffusionMatrixBabyBear;
use p3_field::{PrimeField32, PrimeField64};
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

use sp1_prover::{types::HashableKey, utils::words_to_bytes, InnerSC, ShrinkAir};
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

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
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
    let prover: SP1Prover = SP1Prover::new();
    let merkle_tree_height = prover.recursion_vk_tree.height;
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
        true, // value_assertions enabled - required for WE/statement binding security
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

fn write_u64le_to(w: &mut impl std::io::Write, xs: &[u64]) {
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
}

fn extract_public_inputs_from_shrink(
    input: &SP1CompressWithVKeyWitnessValues<BabyBearPoseidon2>,
) -> ([u8; 32], [u8; 32], [u32; 8], [u32; 8]) {
    let (vk, proof) = input
        .compress_val
        .vks_and_proofs
        .first()
        .expect("expected one shrink proof");
    let vk_hash = vk.bytes32_raw();
    let pv: &sp1_recursion_core::air::RecursionPublicValues<BabyBear> =
        proof.public_values.as_slice().borrow();
    let mut sp1_vk_digest_words = [0u32; 8];
    for (i, x) in pv.sp1_vk_digest.iter().copied().enumerate().take(8) {
        sp1_vk_digest_words[i] = x.as_canonical_u32();
    }
    let mut pv_digest_words = [0u32; 8];
    for (i, x) in pv.digest.iter().copied().enumerate().take(8) {
        pv_digest_words[i] = x.as_canonical_u32();
    }
    let bytes = words_to_bytes(&pv.committed_value_digest);
    let mut committed_values_digest = [0u8; 32];
    for (i, b) in bytes.iter().enumerate().take(32) {
        committed_values_digest[i] = b.as_canonical_u32() as u8;
    }
    (vk_hash, committed_values_digest, sp1_vk_digest_words, pv_digest_words)
}

/// Best-effort extraction of (vk_hash, committed_values_digest) from `SHRINK_PROOF_CACHE`
/// without re-proving. Useful for shape-only runs where we still want to log the program id.
fn try_load_public_inputs_from_shrink_cache() -> Option<([u8; 32], [u8; 32])> {
    let path = std::env::var("SHRINK_PROOF_CACHE").ok()?;
    if !std::path::Path::new(&path).exists() {
        return None;
    }
    let file = std::fs::File::open(&path).ok()?;
    let shrink: SP1ReduceProof<InnerSC> = bincode::deserialize_from(file).ok()?;

    let vk_hash = shrink.vk.bytes32_raw();
    let pv: &sp1_recursion_core::air::RecursionPublicValues<BabyBear> =
        shrink.proof.public_values.as_slice().borrow();
    let bytes = words_to_bytes(&pv.committed_value_digest);
    let mut committed_values_digest = [0u8; 32];
    for (i, b) in bytes.iter().enumerate().take(32) {
        committed_values_digest[i] = b.as_canonical_u32() as u8;
    }
    Some((vk_hash, committed_values_digest))
}

fn write_witness_bundle(
    path: &str,
    r1lf: &sp1_recursion_compiler::r1cs::lf::R1CSLf,
    witness: &[u64],
    vk_hash: &[u8; 32],
    committed_values_digest: &[u8; 32],
) {
    const MAGIC: &[u8; 4] = b"SP1W";
    const VERSION: u32 = 1;
    let file = std::fs::File::create(path).expect("create SP1_WITNESS");
    let mut w = std::io::BufWriter::with_capacity(256 * 1024 * 1024, file);
    w.write_all(MAGIC).expect("write bundle magic");
    w.write_all(&VERSION.to_le_bytes())
        .expect("write bundle version");
    w.write_all(&r1lf.digest()).expect("write r1lf digest");
    let len = witness.len() as u64;
    w.write_all(&len.to_le_bytes())
        .expect("write bundle num_vars");
    w.write_all(vk_hash).expect("write vk_hash");
    w.write_all(committed_values_digest)
        .expect("write committed_values_digest");
    write_u64le_to(&mut w, witness);
    w.flush().expect("flush bundle");
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
    let mut shrink = prover.shrink(compressed, opts).unwrap();
    fix_public_values_digest(&mut shrink.proof.public_values);

    // The shrink-proof verifier circuit verifies the *shrink* proof (vk+proof) with merkle proofs.
    let input = sp1_recursion_circuit::machine::SP1CompressWitnessValues {
        vks_and_proofs: vec![(shrink.vk.clone(), shrink.proof.clone())],
        is_complete: true,
    };
    let input_with_merkle = prover.make_merkle_proofs(input);
    (prover, input_with_merkle)
}

fn load_or_build_input_with_merkle(
) -> (SP1Prover, SP1CompressWithVKeyWitnessValues<BabyBearPoseidon2>, bool) {
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
            let mut shrink: SP1ReduceProof<InnerSC> =
                bincode::deserialize_from(file).expect("deserialize SHRINK_PROOF_CACHE");
            fix_public_values_digest(&mut shrink.proof.public_values);

            let input = sp1_recursion_circuit::machine::SP1CompressWitnessValues {
                vks_and_proofs: vec![(shrink.vk.clone(), shrink.proof.clone())],
                is_complete: true,
            };
            let input_with_merkle = prover.make_merkle_proofs(input);
            println!("Loaded shrink proof from SHRINK_PROOF_CACHE={path}");
            return (prover, input_with_merkle, true);
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
        let mut shrink = SP1ReduceProof::<InnerSC> { vk, proof };
        fix_public_values_digest(&mut shrink.proof.public_values);
        let file = std::fs::File::create(path).expect("create SHRINK_PROOF_CACHE");
        bincode::serialize_into(file, &shrink).expect("serialize SHRINK_PROOF_CACHE");
        println!("Cached shrink proof to SHRINK_PROOF_CACHE={path}");
    }

    (prover, input_with_merkle, false)
}

/// Ensure `public_values.digest` matches the Poseidon2 hash of the prefix.
fn fix_public_values_digest(public_values: &mut Vec<BabyBear>) {
    use sp1_recursion_core::air::{NUM_PV_ELMS_TO_HASH, RecursionPublicValues};
    use sp1_recursion_core::{DIGEST_SIZE, HASH_RATE, PERMUTATION_WIDTH};
    use p3_field::AbstractField;
    use p3_symmetric::Permutation;
    use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;
    use std::borrow::BorrowMut;

    let pv: &mut RecursionPublicValues<BabyBear> = public_values.as_mut_slice().borrow_mut();
    let mut state = [BabyBear::zero(); PERMUTATION_WIDTH];
    for chunk in pv.as_array()[..NUM_PV_ELMS_TO_HASH].chunks(HASH_RATE) {
        for (i, v) in chunk.iter().enumerate() {
            state[i] = *v;
        }
        BabyBearPoseidon2::new().perm.permute_mut(&mut state);
    }
    let digest: [BabyBear; DIGEST_SIZE] = state[..DIGEST_SIZE].try_into().unwrap();
    pv.digest.copy_from_slice(&digest);
}

/// Audit that the lifted LF-targeted R1CS cannot exploit modulus wraparound when proven in Frog64
/// under the current SP1/Frog64 boundedness regime (currently `decomp_b=12, k=8` in LF+).
///
/// This is a *sufficient* condition: it uses worst-case magnitude bounds derived from per-row
/// coefficient \(\ell_1\) norms and the per-coordinate witness bound.
fn audit_no_wrap_frog64_lifted(r1lf: &sp1_recursion_compiler::r1cs::lf::R1CSLf) {
    // Frog base field prime (see latticefold `FrogRing64` docs).
    const Q_FROG: u128 = 15912092521325583641u128;
    const Q_HALF: u128 = Q_FROG / 2;
    // SP1/Frog64 boundedness envelope for each scalar witness coordinate:
    // Conservative verifier-semantics envelope used in the LF+ security rationale:
    // - unit-monomial exponent implies per-digit bound D = d/2 - 1 = 31 for Frog64
    // - base b = 12, k = 8 digits => M = D * (b^k - 1)/(b - 1) = 1,211,766,595
    const M: u128 = 1_211_766_595u128;
    const SP1_P_BB: u64 = 2013265921u64;

    if r1lf.p_bb != SP1_P_BB {
        // Not the SP1 BabyBear modulus; this audit is currently specialized to SP1/Frog64.
        return;
    }

    // Boolean vars are heavily used in SP1. If we treat them as "can be as large as M", the
    // bound is far too pessimistic and trips on rows that multiply by a selector bit.
    //
    // We conservatively infer a variable is boolean if the LF-targeted constraints include either:
    //   (1) x * x = x
    //   (2) x * (x - 1) = 0   (or symmetric variants)
    //
    // This does not require any extra flags and runs inside the existing audit gate.
    let mut is_bool: Vec<bool> = vec![false; r1lf.num_vars];

    #[inline]
    fn is_single_var_one(row: &sp1_recursion_compiler::r1cs::lf::SparseRowI64) -> Option<usize> {
        if row.terms.len() != 1 {
            return None;
        }
        let (idx, coeff) = row.terms[0];
        if idx != 0 && coeff == 1 {
            Some(idx)
        } else {
            None
        }
    }

    #[inline]
    fn is_x_minus_one(
        row: &sp1_recursion_compiler::r1cs::lf::SparseRowI64,
        x: usize,
    ) -> bool {
        if row.terms.len() != 2 {
            return false;
        }
        // Allow either order.
        let (i0, c0) = row.terms[0];
        let (i1, c1) = row.terms[1];
        (i0 == x && c0 == 1 && i1 == 0 && c1 == -1) || (i1 == x && c1 == 1 && i0 == 0 && c0 == -1)
    }

    #[inline]
    fn is_one_minus_x(
        row: &sp1_recursion_compiler::r1cs::lf::SparseRowI64,
        x: usize,
    ) -> bool {
        if row.terms.len() != 2 {
            return false;
        }
        let (i0, c0) = row.terms[0];
        let (i1, c1) = row.terms[1];
        (i0 == 0 && c0 == 1 && i1 == x && c1 == -1) || (i1 == 0 && c1 == 1 && i0 == x && c0 == -1)
    }

    #[inline]
    fn is_zero_row(row: &sp1_recursion_compiler::r1cs::lf::SparseRowI64) -> bool {
        row.terms.is_empty()
    }

    for i in 0..r1lf.num_constraints {
        // Pattern (1): x * x = x
        if let (Some(xa), Some(xb), Some(xc)) = (
            is_single_var_one(&r1lf.a[i]),
            is_single_var_one(&r1lf.b[i]),
            is_single_var_one(&r1lf.c[i]),
        ) {
            if xa == xb && xb == xc {
                is_bool[xa] = true;
                continue;
            }
        }
        // Pattern (2): x * (x-1) = 0 or x*(1-x)=0 (and swapped A/B)
        if let Some(x) = is_single_var_one(&r1lf.a[i]) {
            if (is_x_minus_one(&r1lf.b[i], x) || is_one_minus_x(&r1lf.b[i], x)) && is_zero_row(&r1lf.c[i]) {
                is_bool[x] = true;
                continue;
            }
        }
        if let Some(x) = is_single_var_one(&r1lf.b[i]) {
            if (is_x_minus_one(&r1lf.a[i], x) || is_one_minus_x(&r1lf.a[i], x)) && is_zero_row(&r1lf.c[i]) {
                is_bool[x] = true;
                continue;
            }
        }
    }

    // Helper: bound |row · w| given:
    // - w_0 = 1
    // - boolean vars satisfy w_i ∈ {0,1}
    // - all other vars satisfy |w_i| <= M (the LF+ boundedness envelope)
    #[inline]
    fn bound_lin(
        row: &sp1_recursion_compiler::r1cs::lf::SparseRowI64,
        is_bool: &[bool],
        m: u128,
    ) -> u128 {
        let mut acc: u128 = 0;
        for (idx, coeff) in &row.terms {
            let abs = (*coeff).unsigned_abs() as u128;
            let bnd: u128 = if *idx == 0 {
                1
            } else if *idx < is_bool.len() && is_bool[*idx] {
                1
            } else {
                m
            };
            acc = acc.saturating_add(abs.saturating_mul(bnd));
        }
        acc
    }

    #[derive(Clone, Copy)]
    struct RowStats {
        n_terms: usize,
        l1: u128,
        max_abs: u128,
        has_const: bool,
    }

    fn row_stats(row: &sp1_recursion_compiler::r1cs::lf::SparseRowI64) -> RowStats {
        let mut l1: u128 = 0;
        let mut max_abs: u128 = 0;
        let mut has_const = false;
        for (idx, coeff) in &row.terms {
            if *idx == 0 {
                has_const = true;
            }
            let abs = (*coeff).unsigned_abs() as u128;
            l1 = l1.saturating_add(abs);
            max_abs = max_abs.max(abs);
        }
        RowStats {
            n_terms: row.terms.len(),
            l1,
            max_abs,
            has_const,
        }
    }

    fn top_terms(
        row: &sp1_recursion_compiler::r1cs::lf::SparseRowI64,
        k: usize,
    ) -> Vec<(usize, i64)> {
        let mut v: Vec<(usize, i64)> = row.terms.iter().copied().collect();
        v.sort_by_key(|(_idx, coeff)| (-(coeff.unsigned_abs() as i128)) as i128);
        v.truncate(k);
        v
    }

    let mut worst_row: usize = 0;
    let mut worst_bound: u128 = 0;
    let mut worst_a: u128 = 0;
    let mut worst_b: u128 = 0;
    let mut worst_c: u128 = 0;

    let bool_count = is_bool.iter().filter(|&&b| b).count();
    for i in 0..r1lf.num_constraints {
        let ba = bound_lin(&r1lf.a[i], &is_bool, M);
        let bb = bound_lin(&r1lf.b[i], &is_bool, M);
        let bc = bound_lin(&r1lf.c[i], &is_bool, M);
        // Sufficient wrap-prevention check:
        // |(A·w)(B·w) - (C·w)| <= |A·w||B·w| + |C·w| < q_frog
        let row_bound = ba.saturating_mul(bb).saturating_add(bc);
        if row_bound > worst_bound {
            worst_bound = row_bound;
            worst_row = i;
            worst_a = ba;
            worst_b = bb;
            worst_c = bc;
        }
    }

    println!("\n=========================================================");
    println!("R1LF No-Wrap Audit (SP1→Frog64, sufficient bound)");
    println!("=========================================================");
    println!("  q_frog:                 {Q_FROG}");
    println!("  q_frog/2:               {Q_HALF}");
    println!("  audit threshold:        q_frog (requires worst_bound < q_frog)");
    println!("  per-coordinate bound M: {M}");
    println!("  inferred boolean vars:  {bool_count}");
    println!("  worst row index:        {worst_row}");
    println!("  worst |A·w| bound:      {worst_a}");
    println!("  worst |B·w| bound:      {worst_b}");
    println!("  worst |C·w| bound:      {worst_c}");
    println!("  worst |A·w||B·w|+|C·w|: {worst_bound}");

    // Sufficient condition for "no modulus wrap attack" on this constraint family:
    //
    // If the witness boundedness implies |(A·w)(B·w) - (C·w)| < q_frog, then
    // modular equality in the host field implies the corresponding *integer* equality.
    //
    // Using q/2 is a stronger (often too pessimistic) condition. q is enough here because
    // the only multiple of q within (-q, q) is 0.
    if worst_bound >= Q_FROG {
        let arow = &r1lf.a[worst_row];
        let brow = &r1lf.b[worst_row];
        let crow = &r1lf.c[worst_row];
        let sa = row_stats(arow);
        let sb = row_stats(brow);
        let sc = row_stats(crow);
        println!("\n  ---- worst row diagnostics ----");
        println!(
            "  A: n_terms={} has_const={} l1={} max_abs_coeff={}",
            sa.n_terms, sa.has_const, sa.l1, sa.max_abs
        );
        println!(
            "  B: n_terms={} has_const={} l1={} max_abs_coeff={}",
            sb.n_terms, sb.has_const, sb.l1, sb.max_abs
        );
        println!(
            "  C: n_terms={} has_const={} l1={} max_abs_coeff={}",
            sc.n_terms, sc.has_const, sc.l1, sc.max_abs
        );
        let k = 10usize;
        println!("  top {k} |coeff| terms in A: {:?}", top_terms(arow, k));
        println!("  top {k} |coeff| terms in B: {:?}", top_terms(brow, k));
        println!("  top {k} |coeff| terms in C: {:?}", top_terms(crow, k));

        panic!(
            "R1LF no-wrap audit failed: worst_bound={} >= q_frog={} (row={})",
            worst_bound, Q_FROG, worst_row
        );
    }
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
    let want_witness = std::env::var("SP1_WITNESS").is_ok();
    let (maybe_input_with_merkle, input_loaded_from_cache) = if want_witness {
        let (p, input, loaded_from_cache) = load_or_build_input_with_merkle();
        drop(p);
        (Some(input), loaded_from_cache)
    } else {
        (None, false)
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
            // Keep algebraic shape identical to `build_shrink_verifier_ops()`.
            true,
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
    // - If OUT_WITNESS_BUNDLE is set: dump witness+public-input bundle.
    // - Else if SP1_R1LF is set: dump the (shape) R1LF ONLY.
    let out_r1lf = std::env::var("SP1_R1LF").ok();
    let out_witness_bundle = std::env::var("SP1_WITNESS").ok();
    let mut r1cs_stats: Option<(usize, usize, usize, [u8; 32])> = None; // (num_vars, num_constraints, num_public, digest)

    // Compile to R1CS:
    // - In witness mode, we compile a var-map retaining R1CS later (r1cs2), so skip the early compile.
    // - In shape-only mode, compile once here from `ops`.
    let r1cs_shape_only = if !want_witness {
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
        println!("    0x{}", hex32(&digest));
        if let Some((vk_hash, committed_values_digest)) = try_load_public_inputs_from_shrink_cache()
        {
            // `vk_hash` is program/verifier identity and typically treated as "shape-bound" for a
            // fixed program. In shape-only mode we can only show it if the shrink-proof cache exists.
            println!("  vk_hash=0x{} (from SHRINK_PROOF_CACHE)", hex32(&vk_hash));
            println!(
                "  committed_values_digest=0x{} (from SHRINK_PROOF_CACHE)",
                hex32(&committed_values_digest)
            );
        }
        Some(r1cs)
    } else {
        None
    };

    if want_witness {
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
            println!("    0x{}", hex32(&digest));
            let (vk_hash, committed_values_digest, sp1_vk_digest_words, pv_digest_words) =
                extract_public_inputs_from_shrink(input_with_merkle);
            if input_loaded_from_cache {
                println!(
                    "  vk_hash=0x{} (from SHRINK_PROOF_CACHE)",
                    hex32(&vk_hash)
                );
                println!(
                    "  committed_values_digest=0x{} (from SHRINK_PROOF_CACHE)",
                    hex32(&committed_values_digest)
                );
            } else {
                println!("  vk_hash=0x{}", hex32(&vk_hash));
                println!(
                    "  committed_values_digest=0x{}",
                    hex32(&committed_values_digest)
                );
            }

            // Security check: confirm the exported R1CS public inputs (1..=num_public) match
            // the shrink proof's recursion public values.
            //
            // This ensures `num_public` is not "just a header": these coordinates are concrete,
            // statement-defining values and the compiler-produced witness assigns them correctly.
            if r1cs2.num_public == 8 {
                if w_bb.len() < 1 + r1cs2.num_public {
                    panic!(
                        "witness too short for declared public inputs: w_len={} need_at_least={}",
                        w_bb.len(),
                        1 + r1cs2.num_public
                    );
                }
                // Digest-only binding: first 8 public inputs are `RecursionPublicValues.digest`.
                for i in 0..8 {
                    let got_u32 = w_bb[1 + i].as_canonical_u32();
                    let exp_u32 = pv_digest_words[i];
                    if got_u32 != exp_u32 {
                        panic!(
                            "public input mismatch at idx={} (pv.digest[{}]): got={} expected={}",
                            1 + i,
                            i,
                            got_u32,
                            exp_u32
                        );
                    }
                }
                println!("  public_inputs[1..=8] match (RecursionPublicValues.digest)");
            } else if r1cs2.num_public == 40 {
                if w_bb.len() < 1 + r1cs2.num_public {
                    panic!(
                        "witness too short for declared public inputs: w_len={} need_at_least={}",
                        w_bb.len(),
                        1 + r1cs2.num_public
                    );
                }
                // Expected: first 8 are sp1_vk_digest (BabyBear words), next 32 are digest bytes.
                for i in 0..8 {
                    let got_u32 = w_bb[1 + i].as_canonical_u32();
                    let exp_u32 = sp1_vk_digest_words[i];
                    if got_u32 != exp_u32 {
                        panic!(
                            "public input mismatch at idx={} (sp1_vk_digest[{}]): got={} expected={}",
                            1 + i,
                            i,
                            got_u32,
                            exp_u32
                        );
                    }
                }
                for i in 0..32 {
                    let got_u32 = w_bb[1 + 8 + i].as_canonical_u32();
                    let exp_u32 = committed_values_digest[i] as u32;
                    if got_u32 != exp_u32 {
                        panic!(
                            "public input mismatch at idx={} (committed_value_digest[{}]): got={} expected={}",
                            1 + 8 + i,
                            i,
                            got_u32,
                            exp_u32
                        );
                    }
                }
                println!("  public_inputs[1..=40] match (sp1_vk_digest || committed_value_digest)");
            } else if r1cs2.num_public != 0 {
                println!(
                    "  NOTE: num_public={} (expected 8 for digest-only or legacy 40); skipping public-input value check",
                    r1cs2.num_public
                );
            }

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

            println!("  lift+aux compute time (excluding write): {:?}", dt_aux);

            if let Some(bundle_path) = out_witness_bundle.as_deref() {
                let (vk_hash, committed_values_digest, _sp1_vk_digest_words, _pv_digest_words) =
                    extract_public_inputs_from_shrink(input_with_merkle);
                let t_bundle = std::time::Instant::now();
                write_witness_bundle(
                    bundle_path,
                    &r1lf,
                    &w_lf_u64,
                    &vk_hash,
                    &committed_values_digest,
                );
                let dt_bundle = t_bundle.elapsed();
                let bytes = (w_lf_u64.len() as u64) * 8 + 88;
                let mb = bytes as f64 / 1_000_000.0;
                println!(
                    "Wrote witness bundle to {bundle_path} (len={}, {:.2} MB) in {:?}",
                    w_lf_u64.len(),
                    mb,
                    dt_bundle
                );
            }

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
            "  R1LF (in-memory): num_vars={} num_constraints={} num_public={} digest=0x{}",
            r1lf.num_vars,
            r1lf.num_constraints,
            r1lf.num_public,
            hex32(&r1lf.digest())
        );

        // Extend the existing audit gate with a wraparound safety check on the *lifted* instance.
        if std::env::var("R1CS_AUDIT_UNCONSTRAINED").ok().as_deref() == Some("1") {
            audit_no_wrap_frog64_lifted(&r1lf);
        }

        // If SP1_R1LF is also set, reuse existing file if it matches; otherwise rewrite.
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
                    println!("SP1_R1LF exists and matches witness-mode shape; skipping write: {out_path}");
                } else {
                    println!(
                        "SP1_R1LF exists but does NOT match witness-mode shape; rewriting: {out_path}\n  have: num_vars={} num_constraints={} num_public={} p_bb={} digest={:02x?}...\n  want: num_vars={} num_constraints={} num_public={} p_bb={} digest={:02x?}...",
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
                r1lf.save_to_file(out_path).expect("Failed to save SP1_R1LF");
                println!("Wrote R1LF to {out_path} in {:?}", t_save.elapsed());
            }
        }
    } else if let Some(path) = out_r1lf.as_deref() {
        println!("\nLifting R1CS for LF+ (shape mode: write R1LF only)...");
        let t_lift_total = std::time::Instant::now();
        let r1cs = r1cs_shape_only.expect("shape-only R1CS must have been compiled");
        let (r1lf, stats) = lift_r1cs_to_lf_with_linear_carries(&r1cs);

        // Extend the existing audit gate with a wraparound safety check on the *lifted* instance.
        if std::env::var("R1CS_AUDIT_UNCONSTRAINED").ok().as_deref() == Some("1") {
            audit_no_wrap_frog64_lifted(&r1lf);
        }

        let want_digest = r1lf.digest();
        let want_p = r1lf.p_bb;
        let want_nv = r1lf.num_vars;
        let want_nc = r1lf.num_constraints;
        let want_np = r1lf.num_public;
        let mut should_write = true;
        if let Some((d, p, nv, nc, npub)) = read_r1lf_header(path) {
            if d == want_digest && p == want_p && nv == want_nv && nc == want_nc && npub == want_np {
                should_write = false;
                println!("SP1_R1LF exists and matches shape; skipping write: {path}");
            } else {
                println!(
                    "SP1_R1LF exists but differs; rewriting: {path}\n  have: num_vars={} num_constraints={} num_public={} p_bb={} digest={:02x?}...\n  want: num_vars={} num_constraints={} num_public={} p_bb={} digest={:02x?}...",
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
            "  R1LF: num_vars={} num_constraints={} num_public={} r1lf_digest=0x{}",
            r1lf.num_vars,
            r1lf.num_constraints,
            r1lf.num_public,
            hex32(&r1lf.digest())
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

    if !want_witness && out_r1lf.is_none() {
        println!("\nSet SP1_R1LF=/path/to/shrink_verifier.r1lf to write the LF-targeted format.");
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
