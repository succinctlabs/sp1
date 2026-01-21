//! API: Export the SP1 shrink-verifier relation to LF-targeted R1LF + witness bundle.
//!
//! This is a **library** counterpart of the `dump_shrink_verify_constraints` binary, intended for
//! downstream repos (like PVUGC) to call in-process (no subprocesses, no log scraping).
//!
//! Notes:
//! - This is research plumbing; it writes the same on-disk formats that LF+ expects today.
//! - Program selection uses the same environment variables as the binary:
//!   - `ELF_PATH` (optional; otherwise uses the default fibonacci example)
//!   - `ELF_STDIN_U32` (optional; default 10)
//! - Optional caching (same as the binary):
//!   - `SHRINK_PROOF_CACHE=/path/to/shrink_proof.bin`
//!   - `REBUILD_SHRINK_PROOF=1` to force rebuild even if cache exists

use std::borrow::Borrow;
use std::io::Write;
use std::path::Path;

use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_field::{PrimeField32, PrimeField64};
use sp1_core_executor::SP1Context;
use sp1_core_machine::io::SP1Stdin;
use sp1_core_machine::reduce::SP1ReduceProof;
use sp1_recursion_circuit::machine::{PublicValuesOutputDigest, SP1CompressWithVKeyWitnessValues};
use sp1_recursion_circuit::witness::Witnessable;
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_compiler::ir::Builder;
use sp1_recursion_compiler::r1cs::lf::lift_r1cs_to_lf_with_linear_carries_and_witness;
use sp1_recursion_compiler::r1cs::R1CSCompiler;
use sp1_recursion_compiler::{circuit::AsmCompiler, ir::DslIrProgram};
use sp1_recursion_core::Runtime;
use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;
use sp1_stark::{StarkGenericConfig, SP1ProverOpts};

use crate::{types::HashableKey, utils::words_to_bytes, InnerSC, ShrinkAir, SP1Prover};

/// Export the shrink-verifier R1LF and witness bundle to the given paths.
pub fn export_shrink_verifier(r1lf_path: &Path, witness_bundle_path: &Path) -> anyhow::Result<()> {
    // Build a concrete shrink proof input (vk+proof+merkle) so we can materialize a full witness.
    let prover: SP1Prover = SP1Prover::new();
    let input_with_merkle = build_input_with_merkle(&prover)?;

    // Build verifier circuit ops with the real input (keeps shape identical to shape-only build).
    let machine_verified = ShrinkAir::shrink_machine(InnerSC::compressed());
    let mut builder = Builder::<InnerConfig>::default();
    let input = input_with_merkle.read(&mut builder);
    sp1_recursion_circuit::machine::SP1CompressRootVerifierWithVKey::verify(
        &mut builder,
        &machine_verified,
        input,
        true,
        PublicValuesOutputDigest::Reduce,
    );
    let block = builder.into_root_block();

    // Compile the same block and execute it in recursion runtime to fill memory.
    let dsl_program = unsafe { DslIrProgram::new_unchecked(block.clone()) };
    let mut asm = AsmCompiler::<InnerConfig>::default();
    let program = std::sync::Arc::new(asm.compile(dsl_program));

    type F = <InnerSC as StarkGenericConfig>::Val;
    type EF = <InnerSC as StarkGenericConfig>::Challenge;
    let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new(
        program.clone(),
        sp1_stark::BabyBearPoseidon2Inner::new().perm,
    );
    let mut witness_blocks = Vec::new();
    Witnessable::<InnerConfig>::write(&input_with_merkle, &mut witness_blocks);
    let witness_blocks_for_fill = witness_blocks.clone();
    runtime.witness_stream = witness_blocks.into();
    runtime.run()?;

    // Compile to R1CS and generate the full witness in one pass.
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
        // Minimal subset of `parse_mem_id` logic: handle felt/var/ptr/ext... in the same shapes
        // the compiler emits. This matches the exporter binary.
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

    // Lift to LF-targeted R1LF and compute witness (u64) for that lifted instance.
    let (r1lf, _stats, w_lf_u64) = lift_r1cs_to_lf_with_linear_carries_and_witness(&c.r1cs, &w_bb)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Write R1LF.
    r1lf.save_to_file(
        r1lf_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non-utf8 r1lf path"))?,
    )?;

    // Extract (vk_hash, committed_values_digest) and write witness bundle.
    let (vk_hash, committed_values_digest) = extract_public_inputs_from_shrink(&input_with_merkle);
    write_witness_bundle(witness_bundle_path, &r1lf, &w_lf_u64, &vk_hash, &committed_values_digest)?;

    Ok(())
}

fn build_input_with_merkle(
    prover: &SP1Prover,
) -> anyhow::Result<SP1CompressWithVKeyWitnessValues<BabyBearPoseidon2>> {
    // Cache the shrink proof (vk + proof) to avoid regenerating it between runs.
    let cache_path = std::env::var("SHRINK_PROOF_CACHE").ok();
    let force_rebuild = std::env::var("REBUILD_SHRINK_PROOF").ok().as_deref() == Some("1");

    if let (Some(path), false) = (cache_path.as_deref(), force_rebuild) {
        if std::path::Path::new(path).exists() {
            let file = std::fs::File::open(path)?;
            let shrink: SP1ReduceProof<InnerSC> = bincode::deserialize_from(file)?;
            let input = sp1_recursion_circuit::machine::SP1CompressWitnessValues {
                vks_and_proofs: vec![(shrink.vk.clone(), shrink.proof.clone())],
                is_complete: true,
            };
            return Ok(prover.make_merkle_proofs(input));
        }
    }

    let elf_bytes: Vec<u8> = if let Ok(path) = std::env::var("ELF_PATH") {
        std::fs::read(&path)?
    } else {
        load_default_fibonacci_elf_bytes()?
    };
    let opts = SP1ProverOpts::auto();
    let context = SP1Context::default();

    let (_, pk_d, program, vk) = prover.setup(&elf_bytes);
    let mut stdin = SP1Stdin::new();
    let stdin_u32: u32 = std::env::var("ELF_STDIN_U32")
        .ok()
        .as_deref()
        .map(|s| s.parse().expect("failed to parse ELF_STDIN_U32 as u32"))
        .unwrap_or(10);
    stdin.write(&stdin_u32);
    let core_proof = prover.prove_core(&pk_d, program, &stdin, opts, context)?;
    let compressed = prover.compress(&vk, core_proof, vec![], opts)?;
    let shrink = prover.shrink(compressed, opts)?;

    let input = sp1_recursion_circuit::machine::SP1CompressWitnessValues {
        vks_and_proofs: vec![(shrink.vk.clone(), shrink.proof.clone())],
        is_complete: true,
    };
    let input_with_merkle = prover.make_merkle_proofs(input);

    if let Some(path) = cache_path.as_deref() {
        let shrink = SP1ReduceProof::<InnerSC> {
            vk: shrink.vk,
            proof: shrink.proof,
        };
        let file = std::fs::File::create(path)?;
        bincode::serialize_into(file, &shrink)?;
    }

    Ok(input_with_merkle)
}

fn load_default_fibonacci_elf_bytes() -> anyhow::Result<Vec<u8>> {
    // Mirror the binary's behavior: prefer the already-built fibonacci example ELF if present,
    // otherwise build it once.
    let prover_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let examples_dir = prover_dir.join("../../examples");
    let elf_path = examples_dir.join(
        "target/elf-compilation/riscv32im-succinct-zkvm-elf/release/fibonacci-program",
    );
    if elf_path.exists() {
        return Ok(std::fs::read(&elf_path)?);
    }
    let status = std::process::Command::new("cargo")
        .arg("build")
        .arg("-p")
        .arg("fibonacci-script")
        .arg("--release")
        .current_dir(&examples_dir)
        .status()?;
    if !status.success() {
        anyhow::bail!(
            "failed to build default fibonacci ELF; run (cd sp1/examples && cargo build -p fibonacci-script --release) or set ELF_PATH"
        );
    }
    Ok(std::fs::read(&elf_path)?)
}

fn extract_public_inputs_from_shrink(
    input: &SP1CompressWithVKeyWitnessValues<BabyBearPoseidon2>,
) -> ([u8; 32], [u8; 32]) {
    let (vk, proof) = input
        .compress_val
        .vks_and_proofs
        .first()
        .expect("expected one shrink proof");
    let vk_hash = vk.bytes32_raw();
    let pv: &sp1_recursion_core::air::RecursionPublicValues<BabyBear> =
        proof.public_values.as_slice().borrow();
    let bytes = words_to_bytes(&pv.committed_value_digest);
    let mut committed_values_digest = [0u8; 32];
    for (i, b) in bytes.iter().enumerate().take(32) {
        committed_values_digest[i] = b.as_canonical_u32() as u8;
    }
    (vk_hash, committed_values_digest)
}

fn write_witness_bundle(
    path: &Path,
    r1lf: &sp1_recursion_compiler::r1cs::lf::R1CSLf,
    witness: &[u64],
    vk_hash: &[u8; 32],
    committed_values_digest: &[u8; 32],
) -> anyhow::Result<()> {
    const MAGIC: &[u8; 4] = b"SP1W";
    const VERSION: u32 = 1;
    let file = std::fs::File::create(path)?;
    let mut w = std::io::BufWriter::with_capacity(256 * 1024 * 1024, file);
    w.write_all(MAGIC)?;
    w.write_all(&VERSION.to_le_bytes())?;
    w.write_all(&r1lf.digest())?;
    let len = witness.len() as u64;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(vk_hash)?;
    w.write_all(committed_values_digest)?;
    write_u64le_to(&mut w, witness);
    w.flush()?;
    Ok(())
}

fn write_u64le_to(w: &mut impl std::io::Write, xs: &[u64]) {
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

