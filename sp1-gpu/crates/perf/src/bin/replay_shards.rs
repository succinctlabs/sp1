use std::sync::Arc;
use std::time::Instant;

use clap::Parser;
use rand::seq::SliceRandom;
use rand::SeedableRng;
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
    /// Number of total records to replay
    #[arg(long, default_value_t = 15)]
    pub k: usize,
    /// RNG seed for record selection
    #[arg(long, default_value_t = 42)]
    pub seed: u64,
    /// S3 bucket for shard dumps
    #[arg(long, default_value = "sp1-gpu-shard-dumps")]
    pub bucket: String,
    /// Local directory with pre-downloaded shard data (skips S3 downloads)
    #[arg(long)]
    pub local_dir: Option<String>,
}

#[derive(Deserialize)]
struct ConfigEntry {
    program: String,
    inputs: Vec<String>,
}

/// A (program, optional input) combination.
struct Combo {
    program: String,
    input: Option<String>,
}

impl Combo {
    /// S3 prefix where record files live (may include input subfolder).
    fn s3_prefix(&self, bucket: &str) -> String {
        match &self.input {
            None => format!("s3://{}/{}/", bucket, self.program),
            Some(input) => format!("s3://{}/{}/input/{}/", bucket, self.program, input),
        }
    }

    /// S3 prefix at the program level (where vk.bin lives, common to all inputs).
    fn program_s3_prefix(&self, bucket: &str) -> String {
        format!("s3://{}/{}/", bucket, self.program)
    }

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

/// List record files on S3 for a given prefix by parsing `aws s3 ls` output.
fn list_records_on_s3(prefix: &str) -> Vec<String> {
    let output = std::process::Command::new("aws")
        .args(["s3", "ls", prefix])
        .output()
        .expect("failed to run aws s3 ls");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Failed to list S3 prefix {prefix}: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .filter_map(|line| {
            // Lines look like: "2024-01-01 00:00:00     12345 record_0000.bin"
            let filename = line.split_whitespace().last()?;
            if filename.starts_with("record_") && filename.ends_with(".bin") {
                Some(filename.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Download a file from S3 to a local path.
fn s3_download(s3_path: &str, local_path: &std::path::Path) {
    let output = std::process::Command::new("aws")
        .args(["s3", "cp", s3_path, local_path.to_str().unwrap()])
        .output()
        .expect("failed to run aws s3 cp");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Failed to download {s3_path}: {stderr}");
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

    // List available records for each combo.
    let mut combo_records: Vec<(usize, Vec<String>)> = Vec::new();
    for (i, combo) in combos.iter().enumerate() {
        let records = if let Some(ref local_dir) = args.local_dir {
            list_records_local(&combo.local_path(std::path::Path::new(local_dir)))
        } else {
            list_records_on_s3(&combo.s3_prefix(&args.bucket))
        };
        tracing::info!("{}: {} records available", combo.label(), records.len());
        if !records.is_empty() {
            combo_records.push((i, records));
        }
    }

    if combo_records.is_empty() {
        panic!("No records found for any combo");
    }

    struct SelectedCombo {
        combo_idx: usize,
        record_files: Vec<String>,
    }

    // When using --local-dir, use all local records. Otherwise, select k from S3.
    let selections: Vec<SelectedCombo> = if args.local_dir.is_some() {
        combo_records
            .into_iter()
            .map(|(combo_idx, records)| {
                tracing::info!("{}: using all {} local records", combos[combo_idx].label(), records.len());
                SelectedCombo { combo_idx, record_files: records }
            })
            .collect()
    } else {
        let mut rng = rand::rngs::StdRng::seed_from_u64(args.seed);
        let num_active = combo_records.len();
        let base = args.k / num_active;
        let remainder = args.k % num_active;

        combo_records
            .into_iter()
            .enumerate()
            .map(|(slot, (combo_idx, mut available))| {
                let alloc = base + if slot < remainder { 1 } else { 0 };
                let alloc = alloc.min(available.len());

                available.as_mut_slice().shuffle(&mut rng);
                let selected: Vec<String> = available.into_iter().take(alloc).collect();

                tracing::info!("{}: selected {} records", combos[combo_idx].label(), selected.len());
                SelectedCombo { combo_idx, record_files: selected }
            })
            .collect()
    };

    struct ShardJob {
        label: String,
        record_path: std::path::PathBuf,
        vk_path: std::path::PathBuf,
        elf_path: std::path::PathBuf,
    }

    let mut jobs: Vec<ShardJob> = Vec::new();

    // Build jobs — either from local dir or by downloading from S3.
    let _tmp_dir;
    if let Some(ref local_dir) = args.local_dir {
        let local = std::path::Path::new(local_dir);

        for sel in &selections {
            let combo = &combos[sel.combo_idx];
            let record_dir = combo.local_path(local);
            let program_dir = local.join(&combo.program);
            let vk_path = program_dir.join("vk.bin");
            let elf_path = program_dir.join("program.bin");

            for rec_file in &sel.record_files {
                jobs.push(ShardJob {
                    label: format!("{}:{}", combo.label(), rec_file),
                    record_path: record_dir.join(rec_file),
                    vk_path: vk_path.clone(),
                    elf_path: elf_path.clone(),
                });
            }
        }

        _tmp_dir = None;
    } else {
        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let tmp = tmp_dir.path();

        let mut program_assets: std::collections::HashMap<
            String,
            (std::path::PathBuf, std::path::PathBuf),
        > = std::collections::HashMap::new();

        for sel in &selections {
            let combo = &combos[sel.combo_idx];
            let combo_dir = tmp.join(format!("combo_{}", sel.combo_idx));
            std::fs::create_dir_all(&combo_dir).expect("failed to create combo dir");

            let (vk_path, elf_path) = program_assets
                .entry(combo.program.clone())
                .or_insert_with(|| {
                    let program_dir =
                        tmp.join(format!("program_{}", combo.program.replace('/', "_")));
                    std::fs::create_dir_all(&program_dir).expect("failed to create program dir");

                    let vk_path = program_dir.join("vk.bin");
                    let vk_s3 = format!("{}vk.bin", combo.program_s3_prefix(&args.bucket));
                    tracing::info!("Downloading {vk_s3}");
                    s3_download(&vk_s3, &vk_path);

                    let elf_path = program_dir.join("program.bin");
                    let elf_s3 =
                        format!("s3://sp1-testing-suite/{}/program.bin", combo.program);
                    tracing::info!("Downloading {elf_s3}");
                    s3_download(&elf_s3, &elf_path);

                    (vk_path, elf_path)
                })
                .clone();

            let prefix = combo.s3_prefix(&args.bucket);
            for rec_file in &sel.record_files {
                let rec_path = combo_dir.join(rec_file);
                let rec_s3 = format!("{prefix}{rec_file}");
                tracing::info!("Downloading {rec_s3}");
                s3_download(&rec_s3, &rec_path);

                jobs.push(ShardJob {
                    label: format!("{}:{}", combo.label(), rec_file),
                    record_path: rec_path,
                    vk_path: vk_path.clone(),
                    elf_path: elf_path.clone(),
                });
            }
        }

        _tmp_dir = Some(tmp_dir);
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
