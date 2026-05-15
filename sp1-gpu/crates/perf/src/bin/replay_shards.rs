use std::sync::Arc;
use std::time::Instant;

use clap::Parser;
use rand::{seq::SliceRandom, SeedableRng};
use serde::Deserialize;
use slop_algebra::AbstractField;
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_prover::{core_prover_and_verifier, recursion_prover_and_verifier};
use sp1_hypercube::{
    inner_perm,
    prover::{shape_from_record, AirProver},
    MachineVerifyingKey, SP1PcsProofInner, SP1VerifyingKey, DIGEST_SIZE,
};
use sp1_primitives::{SP1ExtensionField, SP1Field, SP1GlobalContext};
use sp1_prover::{
    recursion::recursive_verifier,
    shapes::{SP1RecursionProofShape, DEFAULT_ARITY},
    worker::get_normalize_program,
};
use sp1_recursion_circuit::{machine::SP1NormalizeWitnessValues, witness::Witnessable};
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_executor::Executor;

#[derive(Parser, Debug)]
#[command(author, version, about = "Replay pre-dumped shard records through the GPU prover")]
struct Args {
    /// Path to JSON config file
    #[arg(long)]
    pub config: String,
    /// Local directory with pre-downloaded shard data
    #[arg(long)]
    pub local_dir: String,
    /// Number of shards to replay
    #[arg(long, default_value = "5")]
    pub num_shards_per_run: usize,
    /// Random seed for shuffling shards
    #[arg(long, default_value = "42")]
    pub seed: u64,
    /// If set, also run the normalize phase for each shard after core proving.
    #[arg(long, default_value_t = false)]
    pub normalize: bool,
}

#[derive(Deserialize)]
struct ConfigEntry {
    program: String,
    #[serde(default)]
    inputs: Vec<String>,
}

/// A (program, optional input) combination.
struct Combo {
    program: String,
    input: Option<String>,
}

impl Combo {
    /// Local path where record files live for this combo.
    fn local_path(&self, local_dir: &std::path::Path) -> std::path::PathBuf {
        match &self.input {
            None => local_dir.join(&self.program),
            Some(input) => local_dir.join(&self.program).join("input").join(input),
        }
    }

    fn label(&self) -> String {
        match &self.input {
            None => self.program.clone(),
            Some(input) => format!("{}/input/{}", self.program, input),
        }
    }
}

/// List record files in a local directory.
fn list_records_local(dir: &std::path::Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut records: Vec<String> = entries
        .filter_map(|e| {
            let name = e.ok()?.file_name().to_string_lossy().to_string();
            if name.starts_with("record_") && name.ends_with(".bin") {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    records.sort();
    records
}

#[tokio::main]
#[allow(clippy::print_stdout)]
async fn main() {
    let args = Args::parse();

    dotenv::dotenv().ok();
    sp1_gpu_tracing::init_tracer();

    // Parse config.
    let config_file = std::fs::File::open(&args.config).expect("failed to open config file");
    let entries: Vec<ConfigEntry> =
        serde_json::from_reader(config_file).expect("failed to parse config JSON");

    // Expand entries into combos.
    let combos: Vec<Combo> = entries
        .into_iter()
        .flat_map(|entry| {
            if entry.inputs.is_empty() {
                vec![Combo { program: entry.program, input: None }]
            } else {
                entry
                    .inputs
                    .into_iter()
                    .map(|input| Combo { program: entry.program.clone(), input: Some(input) })
                    .collect()
            }
        })
        .collect();

    if combos.is_empty() {
        panic!("No program combos found in config");
    }

    tracing::info!("Found {} program combos", combos.len());

    let local = std::path::Path::new(&args.local_dir);

    struct ShardJob {
        label: String,
        record_path: std::path::PathBuf,
        vk_path: std::path::PathBuf,
        elf_path: std::path::PathBuf,
    }

    let mut jobs: Vec<ShardJob> = Vec::new();

    for combo in &combos {
        let record_dir = combo.local_path(local);
        let program_dir = local.join(&combo.program);
        let vk_path = program_dir.join("vk.bin");
        let elf_path = program_dir.join("program.bin");

        let mut records = list_records_local(&record_dir);

        // Shuffle and truncate records for this combo. Take at most `num_shards_per_run` records
        // per combo.
        records.shuffle(&mut rand::rngs::StdRng::seed_from_u64(args.seed));
        records.truncate(args.num_shards_per_run);

        tracing::info!("{}: {} records found", combo.label(), records.len());

        for rec_file in &records {
            jobs.push(ShardJob {
                label: format!("{}:{}", combo.label(), rec_file),
                record_path: record_dir.join(rec_file),
                vk_path: vk_path.clone(),
                elf_path: elf_path.clone(),
            });
        }
    }

    if jobs.is_empty() {
        panic!("No shard records found in {}", args.local_dir);
    }

    tracing::info!("{} shard jobs ready, starting GPU proving", jobs.len());

    let normalize = args.normalize;

    // Run GPU proving.
    let timings = sp1_gpu_cudart::spawn(move |t| async move {
        // let worker_builder = cuda_worker_builder(t.clone()).await;

        let permits = sp1_hypercube::prover::ProverSemaphore::new(1);

        let machine = RiscvAir::machine();
        let (core_prover, core_verifier) =
            core_prover_and_verifier(t.clone(), machine.clone()).await;

        // Set up the normalize-phase resources only if requested.
        let normalize_setup = if normalize {
            let recursive_core_verifier = recursive_verifier::<SP1GlobalContext, _, InnerConfig>(
                core_verifier.shard_verifier(),
            );
            let (normalize_prover, compress_verifier) =
                recursion_prover_and_verifier(t.clone(), &machine).await;
            let reduce_shape =
                SP1RecursionProofShape::retrieve_or_compute_reduce_shape(&machine, DEFAULT_ARITY);
            Some((recursive_core_verifier, compress_verifier, normalize_prover, reduce_shape))
        } else {
            None
        };

        let mut timings: Vec<(String, f64, Option<f64>)> = Vec::new();

        for (i, job) in jobs.iter().enumerate() {
            // Deserialize the record.
            let record_bytes = std::fs::read(&job.record_path).expect("failed to read record file");
            let record: ExecutionRecord =
                bincode::deserialize(&record_bytes).expect("failed to deserialize record");

            // Deserialize the VK.
            let vk_bytes = std::fs::read(&job.vk_path).expect("failed to read vk file");
            let vk: MachineVerifyingKey<SP1GlobalContext> =
                bincode::deserialize(&vk_bytes).expect("failed to deserialize vk");

            // Build program from ELF.
            let elf_bytes = std::fs::read(&job.elf_path).expect("failed to read elf file");
            let program =
                Arc::new(Program::from(&elf_bytes).expect("failed to parse ELF into Program"));

            if i == 0 {
                tracing::info!("Warm up run: {}", job.label);
                let start = Instant::now();
                let (_vk, _proof, _) = core_prover
                    .setup_and_prove_shard(
                        program.clone(),
                        record.clone(),
                        Some(vk.clone()),
                        permits.clone(),
                    )
                    .await;
                let elapsed = start.elapsed().as_secs_f64();
                tracing::info!("Warm up run: {} proved in {:.3}s", job.label, elapsed);
            }

            // Compute the normalize input shape from the record before it is moved into the
            // core prover.
            let proof_shape = normalize_setup
                .as_ref()
                .map(|_| shape_from_record(&core_verifier, &record).expect("shape from record"));

            tracing::info!("Proving shard: {}", job.label);
            let start = Instant::now();
            let (_vk, proof, _) = core_prover
                .setup_and_prove_shard(program, record, Some(vk.clone()), permits.clone())
                .await;
            let core_elapsed = start.elapsed().as_secs_f64();
            tracing::info!("Shard {} core proved in {:.3}s", job.label, core_elapsed);

            let normalize_elapsed = if let (
                Some((recursive_core_verifier, compress_verifier, normalize_prover, reduce_shape)),
                Some(proof_shape),
            ) = (normalize_setup.as_ref(), proof_shape)
            {
                let normalize_start = Instant::now();

                let normalize_program = get_normalize_program(
                    SP1VerifyingKey { vk: vk.clone() },
                    &core_verifier,
                    recursive_core_verifier,
                    &proof_shape,
                    reduce_shape,
                    None,
                );

                // Build the witness using the real core proof. The other fields are not checked
                // by the normalize program, so we use the same dummy values that
                // `dummy_input` populates so the executor sees a self-consistent witness.
                let witness: SP1NormalizeWitnessValues<SP1GlobalContext, SP1PcsProofInner> =
                    SP1NormalizeWitnessValues {
                        vk: vk.clone(),
                        shard_proofs: vec![proof],
                        is_complete: false,
                        vk_root: [SP1Field::zero(); DIGEST_SIZE],
                        reconstruct_deferred_digest: [SP1Field::zero(); 8],
                        num_deferred_proofs: SP1Field::zero(),
                    };
                let mut witness_stream = Vec::new();
                Witnessable::<InnerConfig>::write(&witness, &mut witness_stream);

                // Execute the normalize program to produce the recursion record.
                let mut runtime = Executor::<SP1Field, SP1ExtensionField, _>::new(
                    normalize_program.clone(),
                    inner_perm(),
                );
                runtime.witness_stream = witness_stream.into();
                runtime.run().expect("normalize executor failed");
                let mut recursion_record = runtime.record;

                // Generate the dependencies on the recursion record.
                compress_verifier
                    .machine()
                    .generate_dependencies(std::iter::once(&mut recursion_record), None);

                // Setup and prove the normalize shard.
                let (_, _, _) = normalize_prover
                    .setup_and_prove_shard(
                        normalize_program,
                        recursion_record,
                        None,
                        permits.clone(),
                    )
                    .await;
                let elapsed = normalize_start.elapsed().as_secs_f64();
                tracing::info!("Shard {} normalize proved in {:.3}s", job.label, elapsed);
                Some(elapsed)
            } else {
                None
            };

            timings.push((job.label.clone(), core_elapsed, normalize_elapsed));
        }

        timings
    })
    .await
    .unwrap();

    // Print summary.
    tracing::info!("\n=== Shard Replay Results ===");
    let mut total_core = 0.0;
    let mut total_normalize = 0.0;
    let mut normalize_count = 0;
    for (label, core_secs, normalize_secs) in &timings {
        match normalize_secs {
            Some(normalize_secs) => {
                tracing::info!(
                    "  {label}: core {core_secs:.3}s, normalize {normalize_secs:.3}s, total \
                     {:.3}s",
                    core_secs + normalize_secs
                );
                total_normalize += normalize_secs;
                normalize_count += 1;
            }
            None => tracing::info!("  {label}: core {core_secs:.3}s"),
        }
        total_core += core_secs;
    }
    let n = timings.len() as f64;
    tracing::info!("  Core total: {total_core:.3}s ({} shards)", timings.len());
    tracing::info!("  Core average: {:.3}s per shard", total_core / n);
    if normalize_count > 0 {
        let nc = normalize_count as f64;
        tracing::info!("  Normalize total: {total_normalize:.3}s ({normalize_count} shards)");
        tracing::info!("  Normalize average: {:.3}s per shard", total_normalize / nc);
        tracing::info!(
            "  Combined total: {:.3}s, combined average: {:.3}s per shard",
            total_core + total_normalize,
            (total_core + total_normalize) / n
        );
    }
}
