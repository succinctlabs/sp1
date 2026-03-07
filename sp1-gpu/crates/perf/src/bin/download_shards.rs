use std::path::{Path, PathBuf};

use clap::Parser;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use serde::Deserialize;

#[derive(Parser, Debug)]
#[command(author, version, about = "Download shard records from S3 to a local directory")]
struct Args {
    /// Path to JSON config file
    #[arg(long)]
    pub config: String,
    /// Number of total records to download
    #[arg(long, default_value_t = 15)]
    pub k: usize,
    /// RNG seed for record selection
    #[arg(long, default_value_t = 42)]
    pub seed: u64,
    /// S3 bucket for shard dumps
    #[arg(long, default_value = "sp1-gpu-shard-dumps")]
    pub bucket: String,
    /// Output directory (default: a new temporary directory)
    #[arg(long)]
    pub output_dir: Option<PathBuf>,
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
    fn local_path(&self, local_dir: &Path) -> PathBuf {
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
fn s3_download(s3_path: &str, local_path: &Path) {
    let output = std::process::Command::new("aws")
        .args(["s3", "cp", s3_path, local_path.to_str().unwrap()])
        .output()
        .expect("failed to run aws s3 cp");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Failed to download {s3_path}: {stderr}");
    }
}

#[allow(clippy::print_stdout)]
fn main() {
    let args = Args::parse();

    tracing_subscriber::fmt::init();

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
        let records = list_records_on_s3(&combo.s3_prefix(&args.bucket));
        tracing::info!("{}: {} records available", combo.label(), records.len());
        if !records.is_empty() {
            combo_records.push((i, records));
        }
    }

    if combo_records.is_empty() {
        panic!("No records found for any combo");
    }

    // Select k records distributed across combos.
    let mut rng = rand::rngs::StdRng::seed_from_u64(args.seed);
    let num_active = combo_records.len();
    let base = args.k / num_active;
    let remainder = args.k % num_active;

    struct SelectedCombo {
        combo_idx: usize,
        record_files: Vec<String>,
    }

    let selections: Vec<SelectedCombo> = combo_records
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
        .collect();

    // Determine output directory.
    let output_dir = args.output_dir.unwrap_or_else(|| {
        let dir = std::env::temp_dir().join("shard-replay");
        std::fs::create_dir_all(&dir).expect("failed to create output dir");
        dir
    });
    std::fs::create_dir_all(&output_dir).expect("failed to create output dir");

    // Download files.
    let mut downloaded_programs = std::collections::HashSet::new();

    for sel in &selections {
        let combo = &combos[sel.combo_idx];
        let record_dir = combo.local_path(&output_dir);
        std::fs::create_dir_all(&record_dir).expect("failed to create record dir");

        // Download vk.bin and program.bin once per program.
        if downloaded_programs.insert(combo.program.clone()) {
            let program_dir = output_dir.join(&combo.program);
            std::fs::create_dir_all(&program_dir).expect("failed to create program dir");

            let vk_path = program_dir.join("vk.bin");
            if !vk_path.exists() {
                let vk_s3 = format!("{}vk.bin", combo.program_s3_prefix(&args.bucket));
                tracing::info!("Downloading {vk_s3}");
                s3_download(&vk_s3, &vk_path);
            } else {
                tracing::info!("Skipping existing vk for {}", combo.program);
            }

            let elf_path = program_dir.join("program.bin");
            if !elf_path.exists() {
                let elf_s3 = format!("s3://sp1-testing-suite/{}/program.bin", combo.program);
                tracing::info!("Downloading {elf_s3}");
                s3_download(&elf_s3, &elf_path);
            } else {
                tracing::info!("Skipping existing elf for {}", combo.program);
            }
        }

        // Download selected record files.
        let prefix = combo.s3_prefix(&args.bucket);
        for rec_file in &sel.record_files {
            let rec_path = record_dir.join(rec_file);
            if !rec_path.exists() {
                let rec_s3 = format!("{prefix}{rec_file}");
                tracing::info!("Downloading {rec_s3}");
                s3_download(&rec_s3, &rec_path);
            } else {
                tracing::info!("Skipping existing {rec_file}");
            }
        }
    }

    let total: usize = selections.iter().map(|s| s.record_files.len()).sum();
    println!("{}", output_dir.display());
    eprintln!("Download complete: {total} record(s) in {}", output_dir.display());
}
