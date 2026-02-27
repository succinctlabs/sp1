use std::sync::Arc;
use std::time::Instant;

use clap::Parser;
use serde::Deserialize;
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_gpu_prover::cuda_worker_builder;
use sp1_hypercube::{prover::AirProver, MachineVerifyingKey};
use sp1_primitives::SP1GlobalContext;

#[derive(Parser, Debug)]
#[command(author, version, about = "Replay pre-dumped shard records through the GPU prover")]
struct Args {
    /// Path to JSON config file
    #[arg(long)]
    pub config: String,
    /// Local directory with pre-downloaded shard data
    #[arg(long)]
    pub local_dir: String,
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
    let config_text = std::fs::read_to_string(&args.config).expect("failed to read config file");
    let entries: Vec<ConfigEntry> =
        serde_json::from_str(&config_text).expect("failed to parse config JSON");

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

        let records = list_records_local(&record_dir);
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

    // Run GPU proving.
    let timings = sp1_gpu_cudart::spawn(move |t| async move {
        let worker_builder = cuda_worker_builder(t.clone()).await;

        let (core_prover, permits) = worker_builder
            .core_air_prover_and_permits()
            .expect("core_air_prover_and_permits not set");

        let mut timings: Vec<(String, f64)> = Vec::new();

        for job in &jobs {
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

            tracing::info!("Proving shard: {}", job.label);
            let start = Instant::now();
            let (_vk, _proof, _permit) =
                core_prover.setup_and_prove_shard(program, record, Some(vk), permits.clone()).await;
            let elapsed = start.elapsed().as_secs_f64();

            tracing::info!("Shard {} proved in {:.3}s", job.label, elapsed);
            timings.push((job.label.clone(), elapsed));
        }

        timings
    })
    .await
    .unwrap();

    // Print summary.
    println!("\n=== Shard Replay Results ===");
    let mut total = 0.0;
    for (label, secs) in &timings {
        println!("  {label}: {secs:.3}s");
        total += secs;
    }
    println!("  Total: {total:.3}s ({} shards)", timings.len());
    println!("  Average: {:.3}s per shard", total / timings.len() as f64);
}
