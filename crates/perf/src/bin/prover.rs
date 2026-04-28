//! Interactive SP1 prover CLI scaffolding.
//!
//! Reads `<program> [param]` lines from stdin and resolves each into a `(program_bytes, stdin)`
//! pair using the same convention as the `sp1-gpu-perf` `node` binary. Prover client init and
//! proving logic are intentionally not wired up yet.

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use chrono::Utc;
use clap::{Parser, ValueEnum};
use rustyline::{error::ReadlineError, history::FileHistory, Editor};
use sp1_core_machine::io::SP1Stdin;
use sp1_perf::{get_input, get_program};
use sp1_sdk::{network::NetworkMode, prelude::*, ProverClient, SP1ProofMode};
use tracing::Instrument;

const CSV_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/data/measurements.csv");
const CSV_HEADER: &str = "timestamp,program,param,mode,cycles,gas,elf_bytes,\
                          execute_secs,setup_secs,prove_secs,khz,mgas_per_s\n";

struct CsvLogger {
    file: File,
    path: PathBuf,
}

impl CsvLogger {
    fn open() -> std::io::Result<Self> {
        let path = PathBuf::from(CSV_PATH);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let new_file = !Path::new(&path).exists();
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        if new_file {
            file.write_all(CSV_HEADER.as_bytes())?;
        }
        Ok(Self { file, path })
    }

    #[allow(clippy::too_many_arguments)]
    fn append(&mut self, m: &Measurement) -> std::io::Result<()> {
        let line = format!(
            "{ts},{program},{param},{mode},{cycles},{gas},{elf_bytes},\
             {execute:.6},{setup:.6},{prove:.6},{khz:.3},{mgas:.3}\n",
            ts = Utc::now().to_rfc3339(),
            program = csv_escape(&m.program),
            param = csv_escape(&m.param),
            mode = m.mode.as_str(),
            cycles = m.cycles,
            gas = m.gas.map(|g| g.to_string()).unwrap_or_default(),
            elf_bytes = m.elf_bytes,
            execute = m.execute.as_secs_f64(),
            setup = m.setup.as_secs_f64(),
            prove = m.prove.as_secs_f64(),
            khz = m.khz(),
            mgas = m.mgas_per_s().unwrap_or(0.0),
        );
        self.file.write_all(line.as_bytes())?;
        self.file.flush()
    }
}

struct Measurement {
    program: String,
    param: String,
    mode: ProofModeArg,
    cycles: u64,
    gas: Option<u64>,
    elf_bytes: usize,
    execute: Duration,
    setup: Duration,
    prove: Duration,
}

impl Measurement {
    fn khz(&self) -> f64 {
        let secs = self.prove.as_secs_f64();
        if secs > 0.0 {
            self.cycles as f64 / (secs * 1_000.0)
        } else {
            0.0
        }
    }

    fn mgas_per_s(&self) -> Option<f64> {
        let secs = self.prove.as_secs_f64();
        let gas = self.gas? as f64;
        if secs > 0.0 {
            Some(gas / (secs * 1_000_000.0))
        } else {
            Some(0.0)
        }
    }

    fn print(&self) {
        let gas_str = self.gas.map(|g| g.to_string()).unwrap_or_else(|| "n/a".into());
        let mgas_str = self.mgas_per_s().map(|v| format!("{v:.3}")).unwrap_or_else(|| "n/a".into());
        println!(
            "[sp1-perf] {prog} (param={param:?}, mode={mode}):\n  \
             cycles : {cycles}\n  \
             gas    : {gas}\n  \
             elf    : {elf} bytes\n  \
             execute: {exec:?}\n  \
             setup  : {setup:?}\n  \
             prove  : {prove:?}\n  \
             khz    : {khz:.3}\n  \
             Mgas/s : {mgas}",
            prog = self.program,
            param = self.param,
            mode = self.mode.as_str(),
            cycles = self.cycles,
            gas = gas_str,
            elf = self.elf_bytes,
            exec = self.execute,
            setup = self.setup,
            prove = self.prove,
            khz = self.khz(),
            mgas = mgas_str,
        );
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ProofModeArg {
    Core,
    Compressed,
    Plonk,
    Groth16,
}

impl ProofModeArg {
    fn as_str(self) -> &'static str {
        match self {
            ProofModeArg::Core => "core",
            ProofModeArg::Compressed => "compressed",
            ProofModeArg::Plonk => "plonk",
            ProofModeArg::Groth16 => "groth16",
        }
    }

    fn to_proof_mode(self) -> SP1ProofMode {
        match self {
            ProofModeArg::Core => SP1ProofMode::Core,
            ProofModeArg::Compressed => SP1ProofMode::Compressed,
            ProofModeArg::Plonk => SP1ProofMode::Plonk,
            ProofModeArg::Groth16 => SP1ProofMode::Groth16,
        }
    }
}

/// Per-request flags parsed from each REPL line.
#[derive(Parser, Debug)]
#[command(name = "prove", no_binary_name = true, disable_help_flag = true)]
struct ProveArgs {
    /// Program name (sp1-gpu-perf node format: 'local-<name>' or s3 path).
    program: String,
    /// Optional program-specific parameter.
    #[arg(default_value = "")]
    param: String,
    /// Proof mode.
    #[arg(short, long, value_enum, default_value_t = ProofModeArg::Compressed)]
    mode: ProofModeArg,
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[derive(Default)]
struct Caches {
    programs: HashMap<String, Arc<Vec<u8>>>,
    inputs: HashMap<(String, String), Arc<SP1Stdin>>,
}

impl Caches {
    fn program(&mut self, program: &str) -> Result<(Arc<Vec<u8>>, bool), String> {
        if let Some(bytes) = self.programs.get(program) {
            return Ok((Arc::clone(bytes), true));
        }
        let bytes = Arc::new(catch_panic(|| get_program(program))?);
        self.programs.insert(program.to_string(), Arc::clone(&bytes));
        Ok((bytes, false))
    }

    fn input(&mut self, program: &str, param: &str) -> Result<(Arc<SP1Stdin>, bool), String> {
        let key = (program.to_string(), param.to_string());
        if let Some(stdin) = self.inputs.get(&key) {
            return Ok((Arc::clone(stdin), true));
        }
        let stdin = Arc::new(catch_panic(|| get_input(program, param))?);
        self.inputs.insert(key, Arc::clone(&stdin));
        Ok((stdin, false))
    }
}

fn catch_panic<T>(f: impl FnOnce() -> T + std::panic::UnwindSafe) -> Result<T, String> {
    std::panic::catch_unwind(f).map_err(|e| {
        if let Some(s) = e.downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = e.downcast_ref::<String>() {
            s.clone()
        } else {
            "panic during program/input resolution".to_string()
        }
    })
}

enum Command {
    Prove(ProveArgs),
    Help,
    Quit,
}

fn print_help() {
    eprintln!("Commands:");
    eprintln!("  <program> [param] [--mode <mode>]   Prove the program.");
    eprintln!("    program:  'local-<name>' uses a built-in ELF (fibonacci, sha2, keccak),");
    eprintln!("              otherwise loaded from s3://sp1-testing-suite/<program>/");
    eprintln!("    param:    program-specific (e.g. fibonacci length, s3 input file).");
    eprintln!("    --mode:   core | compressed | groth16 | plonk (default: compressed)");
    eprintln!("  help | h | ?                         Show this help");
    eprintln!("  quit | exit | q                      Exit");
}

fn history_path() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".sp1-perf-history"))
}

async fn read_command(editor: &mut Editor<(), FileHistory>) -> Option<Command> {
    loop {
        // rustyline is sync — run on the blocking pool so the reactor stays free.
        // Move the editor in and back out via spawn_blocking so we keep ownership across calls.
        let mut owned = std::mem::replace(editor, Editor::<(), FileHistory>::new().ok()?);
        let (returned, result) = tokio::task::spawn_blocking(move || {
            let r = owned.readline("sp1-perf> ");
            (owned, r)
        })
        .await
        .expect("readline task panicked");
        *editor = returned;

        let line = match result {
            Ok(line) => line,
            Err(ReadlineError::Eof) | Err(ReadlineError::Interrupted) => return None,
            Err(e) => {
                eprintln!("readline error: {e}");
                return None;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let _ = editor.add_history_entry(trimmed);

        match trimmed {
            "quit" | "exit" | "q" => return Some(Command::Quit),
            "help" | "h" | "?" => return Some(Command::Help),
            _ => {}
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        match ProveArgs::try_parse_from(tokens) {
            Ok(args) => return Some(Command::Prove(args)),
            Err(e) => {
                let _ = e.print();
                continue;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    sp1_sdk::utils::setup_logger();

    eprintln!("[sp1-perf] initializing prover client...");
    let client = ProverClient::builder()
        .network_for(NetworkMode::Reserved)
        .build()
        .instrument(tracing::info_span!("Initialize prover"))
        .await;
    eprintln!("[sp1-perf] prover client initialized: ");

    let mut editor: Editor<(), FileHistory> =
        Editor::new().expect("failed to initialize line editor");
    let history = history_path();
    if let Some(ref p) = history {
        let _ = editor.load_history(p);
    }
    let mut caches = Caches::default();
    let mut csv = match CsvLogger::open() {
        Ok(c) => {
            eprintln!("[sp1-perf] logging measurements to {}", c.path.display());
            Some(c)
        }
        Err(e) => {
            eprintln!("[sp1-perf] could not open csv log ({e}); measurements will not be saved");
            None
        }
    };
    eprintln!("[sp1-perf] ready. type 'help' for commands.");

    loop {
        let cmd = match read_command(&mut editor).await {
            Some(cmd) => cmd,
            None => break,
        };
        match cmd {
            Command::Quit => break,
            Command::Help => print_help(),
            Command::Prove(req) => {
                let (program_bytes, program_hit) = match caches.program(&req.program) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("[sp1-perf] error fetching program: {e}");
                        continue;
                    }
                };
                let (stdin, input_hit) = match caches.input(&req.program, &req.param) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("[sp1-perf] error fetching input: {e}");
                        continue;
                    }
                };
                eprintln!(
                    "[sp1-perf] got program and input for {} (param={:?}): \
                     elf={} bytes [{}], stdin buffers={} [{}]",
                    req.program,
                    req.param,
                    program_bytes.len(),
                    if program_hit { "cached" } else { "fetched" },
                    stdin.buffer.len(),
                    if input_hit { "cached" } else { "fetched" },
                );
                let elf = Elf::from(program_bytes.as_slice());
                let stdin = (*stdin).clone();

                let exec_start = tokio::time::Instant::now();
                let (_, report) =
                    client.execute(elf.clone(), stdin.clone()).calculate_gas(true).await.unwrap();
                let execute_time = exec_start.elapsed();

                let setup_start = tokio::time::Instant::now();
                let pk = client.setup(elf).instrument(tracing::info_span!("setup")).await.unwrap();
                let setup_time = setup_start.elapsed();

                let prove_start = tokio::time::Instant::now();
                let proof = client
                    .prove(&pk, stdin)
                    .mode(req.mode.to_proof_mode())
                    .skip_simulation(true)
                    .cycle_limit(u64::MAX)
                    .gas_limit(u64::MAX)
                    .await
                    .unwrap();
                let prove_time = prove_start.elapsed();

                // Verify the proof
                client.verify(&proof, pk.verifying_key(), None).unwrap();

                let measurement = Measurement {
                    program: req.program.clone(),
                    param: req.param.clone(),
                    mode: req.mode,
                    cycles: report.total_instruction_count(),
                    gas: report.gas(),
                    elf_bytes: program_bytes.len(),
                    execute: execute_time,
                    setup: setup_time,
                    prove: prove_time,
                };
                measurement.print();

                if let Some(csv) = csv.as_mut() {
                    if let Err(e) = csv.append(&measurement) {
                        eprintln!("[sp1-perf] failed to append to csv: {e}");
                    }
                }
            }
        }
    }
    if let Some(ref p) = history {
        let _ = editor.save_history(p);
    }
    eprintln!("[sp1-perf] bye");
}
