use powdr_autoprecompiles::{PgoData, PgoType};
use clap::Parser;
use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;
use std::sync::Arc;
use sp1_core_machine::autoprecompiles::sp1_configs;
use sp1_core_machine::autoprecompiles::execution_profile_from_program;
use sp1_core_machine::autoprecompiles::CompiledProgram;
use sp1_core_executor::Program;
use std::path::PathBuf;

const ELF: Elf = include_elf!("keccak-bench-program");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of hashes to compute
    #[arg(long)]
    num_hashes: usize,

    /// Whether to use the manual Keccak precompile
    #[arg(long)]
    manual: bool,

    /// The number of APCs to generate
    #[arg(long, default_value_t = 0)]
    apcs: usize,

    /// Instead of proving, export an apc-optimizer benchmark set to `<out>/keccak`.
    /// Use with `--manual false` so the hot software-keccak blocks become APCs.
    #[arg(long)]
    bench_out: Option<PathBuf>,

    /// Number of top-ranked (cell PGO) candidates to export in `--bench-out` mode.
    #[arg(long, default_value_t = 1)]
    bench_top: u64,
}

#[tokio::main]
async fn main() {
    // Generate proof.
    // utils::setup_tracer();
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();
    let num_hashes: usize = args.num_hashes;
    let manual = args.manual;
    let state = vec![0u8; 32];

    let mut stdin = SP1Stdin::new();
    stdin.write(&manual);
    stdin.write(&num_hashes);
    stdin.write(&state);

    if let Some(out) = args.bench_out {
        let out_dir = out.join("keccak");
        let note = format!("keccak-bench (manual={manual}), {num_hashes} hashes, cell PGO");
        println!("[powdr] Exporting benchmark set to {} ...", out_dir.display());
        sp1_core_machine::autoprecompiles::benchmark::export_benchmark_set(
            &ELF,
            stdin,
            &out_dir,
            args.bench_top,
            &note,
        );
        println!("[powdr] Done!");
        return;
    }

    let apcs = if args.apcs > 0 {
        let program = Arc::new(Program::from(&ELF).unwrap());
        let execution_profile = execution_profile_from_program(program, stdin.clone());
        let path = std::path::Path::new("apc_candidates");
        let (generate, select) = sp1_configs(args.apcs as u64, 0, PgoType::Cell);
        let generate = generate.with_apc_candidates_dir(path);
        let pgo_data = PgoData::Cell(execution_profile, None);
        let compiled_program = CompiledProgram::new(&ELF, generate, select, pgo_data);

        compiled_program
            .apcs_and_stats
            .into_iter()
            .map(|a| a.into_parts())
            .map(|(apc, _, _)| apc)
            .collect()
    } else {
        Vec::new()
    };

    let client = ProverClient::from_env_with_machine(RiscvAir::machine_with_apcs(apcs)).await;
    let pk = client.setup(ELF).await.expect("setup failed");
    let proof = client.prove(&pk, stdin).core().await.expect("proving failed");

    // Verify proof.
    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}