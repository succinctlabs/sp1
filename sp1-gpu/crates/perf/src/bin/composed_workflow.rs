use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Parser, ValueEnum};
use serde::Deserialize;
use sp1_gpu_perf::get_program_and_input;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Mode {
    /// Run the `node` binary locally with `SP1_RECORD_WRITE_DIR` pointing into `dir`,
    /// then replay from `dir`.
    Local,
    /// Skip dumping — assume `dir` already contains shard records — and just replay.
    LocalWithCache,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Compose dump/replay shard workflows end-to-end")]
struct Args {
    /// Workflow mode.
    #[arg(long, value_enum)]
    pub mode: Mode,
    /// Persistent local directory used as the download / dump / replay root.
    /// Created if it does not exist; never deleted (so the dir can be reused later).
    #[arg(long)]
    pub dir: String,
    /// Path to JSON config file (same schema as download-shards / replay-shards).
    #[arg(long)]
    pub config: String,
    /// Optional number of shards per "program/input" pair to replay.
    #[arg(long)]
    pub k: Option<usize>,
    /// If set, run `replay-shards` under `nsys profile`.
    #[arg(long, default_value_t = false)]
    pub nsys_tracing: bool,
    /// If set, forward `--normalize` to `replay-shards` so it runs the normalize phase
    /// for each shard after core proving.
    #[arg(long, default_value_t = false)]
    pub normalize: bool,
}

#[derive(Deserialize)]
struct ConfigEntry {
    program: String,
    #[serde(default)]
    inputs: Vec<String>,
}

struct Combo {
    program: String,
    input: Option<String>,
}

impl Combo {
    /// Where records live for this combo (matches download-shards/replay-shards layout).
    fn record_dir(&self, root: &Path) -> PathBuf {
        match &self.input {
            None => root.join(&self.program),
            Some(input) => root.join(&self.program).join("input").join(input),
        }
    }

    /// Where vk.bin and program.bin live (program-level, shared across inputs).
    fn program_dir(&self, root: &Path) -> PathBuf {
        root.join(&self.program)
    }

    fn label(&self) -> String {
        match &self.input {
            None => self.program.clone(),
            Some(input) => format!("{}/input/{}", self.program, input),
        }
    }
}

fn parse_combos(config_path: &str) -> Vec<Combo> {
    let text = std::fs::read_to_string(config_path).expect("failed to read config");
    let entries: Vec<ConfigEntry> =
        serde_json::from_str(&text).expect("failed to parse config JSON");
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
        panic!("config contained no program combos");
    }
    combos
}

/// Strip env vars that `cargo run` injects into the spawned binary's env. Those vars
/// (CARGO_MANIFEST_DIR, CARGO_PKG_*, CARGO_BIN_NAME, …) leak into the nested `cargo build`
/// invocation here and poison build-script fingerprints (e.g. ring's), making the inner
/// build's fingerprint differ from a direct shell `cargo build`.
fn strip_cargo_run_env(cmd: &mut Command) {
    cmd.env_remove("CARGO");
    cmd.env_remove("CARGO_MANIFEST_DIR");
    cmd.env_remove("CARGO_MANIFEST_PATH");
    cmd.env_remove("CARGO_BIN_NAME");
    cmd.env_remove("CARGO_CRATE_NAME");
    for (k, _) in std::env::vars() {
        if k.starts_with("CARGO_PKG_") {
            cmd.env_remove(&k);
        }
    }
}

/// Build the listed binaries via `cargo build --release` and return their executable paths.
fn build_binaries(bins: &[&str]) -> Vec<PathBuf> {
    let mut cmd = Command::new("cargo");
    strip_cargo_run_env(&mut cmd);
    cmd.arg("build").arg("--release").arg("-p").arg("sp1-gpu-perf");
    for bin in bins {
        cmd.arg("--bin").arg(bin);
    }
    let status = cmd.status().expect("failed to invoke cargo build");
    if !status.success() {
        panic!("cargo build failed for {bins:?}");
    }

    let target_dir = locate_target_dir();
    bins.iter().map(|b| target_dir.join("release").join(b)).collect()
}

fn locate_target_dir() -> PathBuf {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version=1", "--no-deps"])
        .output()
        .expect("failed to run cargo metadata");
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("cargo metadata failed: {stderr}");
    }
    #[derive(Deserialize)]
    struct Metadata {
        target_directory: String,
    }
    let meta: Metadata =
        serde_json::from_slice(&output.stdout).expect("failed to parse cargo metadata");
    PathBuf::from(meta.target_directory)
}

fn run_or_panic(label: &str, mut cmd: Command) {
    tracing::info!("[composed-workflow] {label}: {cmd:?}");
    let status = cmd.status().unwrap_or_else(|e| panic!("failed to spawn {label}: {e}"));
    if !status.success() {
        panic!("{label} exited with {status}");
    }
}

fn run_replay_shards(
    bin: &Path,
    config: &str,
    local_dir: &Path,
    nsys: bool,
    k: Option<usize>,
    normalize: bool,
) {
    let mut cmd = if nsys {
        let mut c = Command::new("nsys");
        c.arg("profile").arg(bin);
        c
    } else {
        Command::new(bin)
    };
    cmd.arg("--config").arg(config).arg("--local-dir").arg(local_dir);
    if let Some(k) = k {
        cmd.arg("--num-shards-per-run").arg(k.to_string());
    }
    if normalize {
        cmd.arg("--normalize");
    }
    let label = if nsys { "nsys profile replay-shards" } else { "replay-shards" };
    run_or_panic(label, cmd);
}

/// Run the `node` binary for one combo, dumping records into the per-combo subdirectory
/// expected by replay-shards. Returns nothing — files end up at the right paths under `root`.
fn run_node_for_combo(node_bin: &Path, combo: &Combo, root: &Path) {
    let record_dir = combo.record_dir(root);
    std::fs::create_dir_all(&record_dir).expect("failed to create record dir");

    // Run `node` with SP1_RECORD_WRITE_DIR pointing at the per-combo record dir.
    // Use core mode and a single iteration so we just dump records once.
    let mut cmd = Command::new(node_bin);
    cmd.arg("--program")
        .arg(&combo.program)
        .arg("--mode")
        .arg("core")
        .arg("--num-iterations")
        .arg("1");
    if let Some(input) = &combo.input {
        cmd.arg("--param").arg(input);
    } else {
        cmd.arg("--param").arg("");
    }
    cmd.env("SP1_RECORD_WRITE_DIR", &record_dir);
    run_or_panic(&format!("node[{}]", combo.label()), cmd);

    // The prover writes vk.bin into SP1_RECORD_WRITE_DIR. replay-shards expects it at
    // <root>/<program>/vk.bin (program level). When the combo has an input, move it up.
    let program_dir = combo.program_dir(root);
    std::fs::create_dir_all(&program_dir).expect("failed to create program dir");
    let vk_at_record = record_dir.join("vk.bin");
    let vk_at_program = program_dir.join("vk.bin");
    if vk_at_record != vk_at_program {
        if vk_at_record.exists() {
            std::fs::rename(&vk_at_record, &vk_at_program).expect("failed to move vk.bin");
        } else if !vk_at_program.exists() {
            panic!("expected vk.bin at {} but it was not produced", vk_at_record.display());
        }
    }

    // Write program.bin from the elf bytes. replay-shards reads it from <program>/program.bin.
    // If the path does not exist, download the program from S3, or copy it from the local cache,
    // according to the logic in `get_program_and_input`.
    let elf_path = program_dir.join("program.bin");
    if !elf_path.exists() {
        let (elf, _stdin) =
            get_program_and_input(combo.program.clone(), combo.input.clone().unwrap_or_default());
        std::fs::write(&elf_path, &elf).expect("failed to write program.bin");
    }
}

#[allow(clippy::print_stdout)]
fn main() {
    let args = Args::parse();
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::init();

    let combos = parse_combos(&args.config);
    tracing::info!("[composed-workflow] {} combos in config", combos.len());

    // Decide which binaries to build based on mode.
    let bins_needed: &[&str] = match args.mode {
        Mode::Local => &["node", "replay-shards"],
        Mode::LocalWithCache => &["replay-shards"],
    };
    let bin_paths = build_binaries(bins_needed);
    let bin = |name: &str| -> PathBuf {
        let idx = bins_needed.iter().position(|b| *b == name).expect("bin not built");
        bin_paths[idx].clone()
    };

    // The persistent root directory for downloads/dumps/replay.
    let root = PathBuf::from(&args.dir);
    std::fs::create_dir_all(&root).expect("failed to create dir");

    // Populate `root` according to mode.
    match args.mode {
        Mode::Local => {
            let node_bin = bin("node");
            for combo in &combos {
                run_node_for_combo(&node_bin, combo, &root);
            }
        }
        Mode::LocalWithCache => {
            // Nothing to populate — `dir` is already expected to contain dumped records.
        }
    }

    run_replay_shards(
        &bin("replay-shards"),
        &args.config,
        &root,
        args.nsys_tracing,
        args.k,
        args.normalize,
    );

    tracing::info!("[composed-workflow] done; replay dir: {}", root.display());
}
