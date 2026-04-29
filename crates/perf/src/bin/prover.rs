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

use anyhow::Context;
use chrono::Utc;
use clap::{Args, Parser, Subcommand, ValueEnum};
use rustyline::{error::ReadlineError, history::FileHistory, Editor};
use sp1_core_machine::io::SP1Stdin;
use sp1_perf::{get_input, get_program};
use sp1_sdk::{network::NetworkMode, prelude::*, NetworkProver, ProverClient, SP1ProofMode};
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

/// Top-level REPL parser. Each line is parsed as a subcommand.
#[derive(Parser, Debug)]
#[command(no_binary_name = true, disable_help_flag = true)]
struct Cli {
    #[command(subcommand)]
    cmd: SubCmd,
}

#[derive(Subcommand, Debug)]
enum SubCmd {
    /// Run the program through execute + setup + prove + verify and log the measurement.
    Prove(ProveArgs),
    /// Run only the executor and report cycles, gas, and execution rate.
    Execute(ExecuteArgs),
    /// List benchmark programs available in s3://sp1-testing-suite/.
    Programs {
        /// Optional substring filter.
        filter: Option<String>,
    },
    /// List input files for a benchmark program (s3://sp1-testing-suite/<program>/input/).
    Inputs {
        /// Program name.
        #[arg(short, long)]
        program: String,
    },
}

#[derive(Args, Debug)]
struct ProveArgs {
    /// Program name. 'local-<name>' uses a built-in ELF (fibonacci, sha2, keccak);
    /// anything else is loaded from s3://sp1-testing-suite/<program>/.
    #[arg(short, long)]
    program: String,
    /// Program-specific input (e.g. fibonacci length, s3 input file basename).
    #[arg(short, long, default_value = "")]
    input: String,
    /// Proof mode.
    #[arg(short, long, value_enum, default_value_t = ProofModeArg::Compressed)]
    mode: ProofModeArg,
}

#[derive(Args, Debug)]
struct ExecuteArgs {
    /// Program name (see `prove --help`).
    #[arg(short, long)]
    program: String,
    /// Program-specific input.
    #[arg(short, long, default_value = "")]
    input: String,
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

fn load_program_and_input(
    caches: &mut Caches,
    program: &str,
    input: &str,
) -> anyhow::Result<(Arc<Vec<u8>>, Arc<SP1Stdin>)> {
    let (program_bytes, program_hit) =
        caches.program(program).map_err(|e| anyhow::anyhow!("fetch program {program}: {e}"))?;
    let (stdin, input_hit) = caches
        .input(program, input)
        .map_err(|e| anyhow::anyhow!("fetch input ({program}, {input:?}): {e}"))?;
    eprintln!(
        "[sp1-perf] got program and input for {program} (input={input:?}): \
         elf={} bytes [{}], stdin buffers={} [{}]",
        program_bytes.len(),
        if program_hit { "cached" } else { "fetched" },
        stdin.buffer.len(),
        if input_hit { "cached" } else { "fetched" },
    );
    Ok((program_bytes, stdin))
}

async fn do_prove(
    client: &NetworkProver,
    caches: &mut Caches,
    args: &ProveArgs,
) -> anyhow::Result<Measurement> {
    let (program_bytes, stdin) = load_program_and_input(caches, &args.program, &args.input)?;
    let elf = Elf::from(program_bytes.as_slice());
    let stdin = (*stdin).clone();

    let exec_start = tokio::time::Instant::now();
    let (_, report) =
        client.execute(elf.clone(), stdin.clone()).calculate_gas(true).await.context("execute")?;
    let execute_time = exec_start.elapsed();

    let setup_start = tokio::time::Instant::now();
    let pk = client.setup(elf).instrument(tracing::info_span!("setup")).await.context("setup")?;
    let setup_time = setup_start.elapsed();

    let prove_start = tokio::time::Instant::now();
    let proof = client
        .prove(&pk, stdin)
        .mode(args.mode.to_proof_mode())
        .skip_simulation(true)
        .cycle_limit(u64::MAX)
        .gas_limit(u64::MAX)
        .await
        .context("prove")?;
    let prove_time = prove_start.elapsed();

    client.verify(&proof, pk.verifying_key(), None).context("verify")?;

    Ok(Measurement {
        program: args.program.clone(),
        param: args.input.clone(),
        mode: args.mode,
        cycles: report.total_instruction_count(),
        gas: report.gas(),
        elf_bytes: program_bytes.len(),
        execute: execute_time,
        setup: setup_time,
        prove: prove_time,
    })
}

struct ExecuteSummary {
    program: String,
    input: String,
    cycles: u64,
    gas: Option<u64>,
    elapsed: Duration,
}

impl ExecuteSummary {
    fn print(&self) {
        let secs = self.elapsed.as_secs_f64();
        let mhz = if secs > 0.0 { self.cycles as f64 / (secs * 1_000_000.0) } else { 0.0 };
        let mgas = self.gas.map(|g| if secs > 0.0 { g as f64 / (secs * 1_000_000.0) } else { 0.0 });
        let gas_str = self.gas.map(|g| g.to_string()).unwrap_or_else(|| "n/a".into());
        let mgas_str = mgas.map(|v| format!("{v:.3}")).unwrap_or_else(|| "n/a".into());
        println!(
            "[sp1-perf] execute {prog} (input={input:?}):\n  \
             cycles : {cycles}\n  \
             gas    : {gas}\n  \
             time   : {time:?}\n  \
             MHz    : {mhz:.3}\n  \
             Mgas/s : {mgas}",
            prog = self.program,
            input = self.input,
            cycles = self.cycles,
            gas = gas_str,
            time = self.elapsed,
            mgas = mgas_str,
        );
    }
}

async fn do_execute(
    client: &NetworkProver,
    caches: &mut Caches,
    args: &ExecuteArgs,
) -> anyhow::Result<ExecuteSummary> {
    let (program_bytes, stdin) = load_program_and_input(caches, &args.program, &args.input)?;
    let elf = Elf::from(program_bytes.as_slice());
    let stdin = (*stdin).clone();

    let exec_start = tokio::time::Instant::now();
    let (_, report) = client.execute(elf, stdin).calculate_gas(true).await.context("execute")?;
    let elapsed = exec_start.elapsed();

    Ok(ExecuteSummary {
        program: args.program.clone(),
        input: args.input.clone(),
        cycles: report.total_instruction_count(),
        gas: report.gas(),
        elapsed,
    })
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
    Sub(SubCmd),
    Help,
    Quit,
}

fn print_help() {
    eprintln!("Commands:");
    eprintln!("  prove   --program <P> [--input <I>] [--mode <M>]");
    eprintln!("            Execute + setup + prove + verify; logs to data/measurements.csv.");
    eprintln!("            mode: core | compressed | groth16 | plonk (default: compressed)");
    eprintln!("  execute --program <P> [--input <I>]");
    eprintln!("            Run only the executor; report cycles, gas, execution rate.");
    eprintln!("  programs [<filter>]");
    eprintln!("            List benchmark programs in s3://sp1-testing-suite/.");
    eprintln!("  inputs  --program <P>");
    eprintln!("            List input files for a benchmark program.");
    eprintln!();
    eprintln!("  Program names: 'local-<name>' uses a built-in ELF (fibonacci, sha2, keccak),");
    eprintln!("                 anything else is fetched from s3://sp1-testing-suite/<program>/.");
    eprintln!();
    eprintln!("  help | h | ?           Show this help");
    eprintln!("  quit | exit | q        Exit");
}

const LOCAL_PROGRAMS: &[&str] = &["local-fibonacci", "local-sha2", "local-keccak"];

fn list_programs(filter: Option<&str>) -> Result<Vec<String>, String> {
    let output = std::process::Command::new("aws")
        .args(["s3", "ls", "--recursive", "s3://sp1-testing-suite/"])
        .output()
        .map_err(|e| format!("failed to run aws: {e}"))?;
    if !output.status.success() {
        return Err(format!("aws s3 ls failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut programs: Vec<String> = stdout
        .lines()
        .filter_map(|line| {
            let path = line.split_whitespace().last()?;
            path.strip_suffix("/program.bin").map(|s| s.to_string())
        })
        .collect();
    programs.sort();
    programs.dedup();
    for local in LOCAL_PROGRAMS {
        programs.push((*local).to_string());
    }
    if let Some(f) = filter {
        programs.retain(|p| p.contains(f));
    }
    Ok(programs)
}

fn list_inputs(program: &str) -> Result<Vec<String>, String> {
    if program.starts_with("local-") {
        return Ok(vec!["<numeric size/length passed via --input>".to_string()]);
    }
    let prefix = format!("s3://sp1-testing-suite/{program}/input/");
    let output = std::process::Command::new("aws")
        .args(["s3", "ls", &prefix])
        .output()
        .map_err(|e| format!("failed to run aws: {e}"))?;
    if !output.status.success() {
        return Err(format!("aws s3 ls failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut inputs: Vec<String> = stdout
        .lines()
        .filter_map(|line| {
            let name = line.split_whitespace().last()?;
            name.strip_suffix(".bin").map(|s| s.to_string())
        })
        .collect();
    inputs.sort();
    Ok(inputs)
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
        match Cli::try_parse_from(tokens) {
            Ok(cli) => return Some(Command::Sub(cli.cmd)),
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
            Command::Sub(SubCmd::Prove(req)) => match do_prove(&client, &mut caches, &req).await {
                Ok(measurement) => {
                    measurement.print();
                    if let Some(csv) = csv.as_mut() {
                        if let Err(e) = csv.append(&measurement) {
                            eprintln!("[sp1-perf] failed to append to csv: {e}");
                        }
                    }
                }
                Err(e) => eprintln!("[sp1-perf] prove failed: {e:#}"),
            },
            Command::Sub(SubCmd::Execute(req)) => {
                match do_execute(&client, &mut caches, &req).await {
                    Ok(summary) => summary.print(),
                    Err(e) => eprintln!("[sp1-perf] execute failed: {e:#}"),
                }
            }
            Command::Sub(SubCmd::Programs { filter }) => {
                let filter_clone = filter.clone();
                let res =
                    tokio::task::spawn_blocking(move || list_programs(filter_clone.as_deref()))
                        .await
                        .expect("listing task panicked");
                match res {
                    Ok(programs) if programs.is_empty() => {
                        eprintln!(
                            "[sp1-perf] no programs found{}",
                            filter.map(|f| format!(" matching {f:?}")).unwrap_or_default(),
                        );
                    }
                    Ok(programs) => {
                        println!("[sp1-perf] {} program(s):", programs.len());
                        for p in &programs {
                            println!("  {p}");
                        }
                    }
                    Err(e) => eprintln!("[sp1-perf] error listing programs: {e}"),
                }
            }
            Command::Sub(SubCmd::Inputs { program }) => {
                let prog = program.clone();
                let res = tokio::task::spawn_blocking(move || list_inputs(&prog))
                    .await
                    .expect("listing task panicked");
                match res {
                    Ok(inputs) if inputs.is_empty() => {
                        eprintln!("[sp1-perf] no inputs found for {program}");
                    }
                    Ok(inputs) => {
                        println!("[sp1-perf] {} input(s) for {program}:", inputs.len());
                        for i in &inputs {
                            println!("  {i}");
                        }
                    }
                    Err(e) => eprintln!("[sp1-perf] error listing inputs: {e}"),
                }
            }
        }
    }
    if let Some(ref p) = history {
        let _ = editor.save_history(p);
    }
    eprintln!("[sp1-perf] bye");
}
