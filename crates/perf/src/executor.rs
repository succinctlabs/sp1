use std::sync::Arc;

use clap::Parser;

use slop_algebra::AbstractField;
use sp1_core_executor::{MinimalExecutor, Program, SP1CoreOpts};
use sp1_core_machine::io::SP1Stdin;
use sp1_hypercube::{septic_digest::SepticDigest, MachineVerifyingKey};
use sp1_primitives::{Elf, SP1Field};
use sp1_prover::{
    worker::{
        CommonProverInput, ProofId, RequesterId, SP1CoreExecutor, SplicingEngine, SplicingWorker,
        TaskContext, TrivialWorkerClient,
    },
    SP1VerifyingKey,
};
use sp1_prover_types::{network_base_types::ProofMode, ArtifactClient, InMemoryArtifactClient};
use sp1_sdk::{setup_logger, MockProver, Prover};
use tokio::sync::mpsc;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "local-fibonacci")]
    pub program: String,
    #[arg(long, default_value = "")]
    pub param: String,
    #[arg(long, default_value = "10")]
    pub splice_workers: usize,
    #[arg(long, default_value = "10")]
    pub splice_buffer: usize,
    #[arg(long, default_value = "2")]
    pub send_workers: usize,
    #[arg(long, default_value = "2")]
    pub send_buffer_size: usize,
    #[arg(long, default_value = None)]
    pub chunk_size: Option<u64>,
    #[arg(long, default_value = "10")]
    pub task_capacity: usize,
    #[arg(long, default_value = "false")]
    pub telemetry: bool,
    #[arg(long, default_value = "gas")]
    pub mode: String,
    #[arg(long, default_value = None)]
    pub cycle_limit: Option<u64>,
    #[arg(long, default_value = "false")]
    pub local: bool,
}

// Executes a program similarly to the cluster controller.
async fn execute_node(args: Args, elf: Vec<u8>, stdin: SP1Stdin) {
    // Initialize the artifact and worker clients
    let artifact_client = InMemoryArtifactClient::new();
    let worker_client = TrivialWorkerClient::new(args.task_capacity, artifact_client.clone());

    let splicing_workers = (0..args.splice_workers)
        .map(|_| {
            SplicingWorker::new(
                artifact_client.clone(),
                worker_client.clone(),
                args.send_workers,
                args.send_buffer_size,
            )
        })
        .collect::<Vec<_>>();

    let splicing_engine = Arc::new(SplicingEngine::new(splicing_workers, args.splice_buffer));

    let proof_id = ProofId::new("bench_pure_execution");
    let parent_id = None;
    let parent_context = None;
    let requester_id = RequesterId::new("bench_pure_execution");

    let dummy_vk = MachineVerifyingKey {
        pc_start: [SP1Field::zero(); 3],
        initial_global_cumulative_sum: SepticDigest::zero(),
        preprocessed_commit: [SP1Field::zero(); 8],
        enable_untrusted_programs: SP1Field::zero(),
    };
    let dummy_vk = SP1VerifyingKey { vk: dummy_vk };

    let common_input = CommonProverInput {
        vk: dummy_vk,
        deferred_digest: [0; 8],
        mode: ProofMode::Core,
        num_deferred_proofs: 0,
        nonce: [0; 4],
    };
    let common_input_artifact =
        artifact_client.create_artifact().expect("failed to create artifact");
    artifact_client
        .upload(&common_input_artifact, common_input)
        .await
        .expect("failed to upload common input");

    let (sender, mut receiver) = mpsc::unbounded_channel();

    let elf_artifact = artifact_client.create_artifact().expect("failed to create artifact");
    let elf_bytes = elf.to_vec();
    artifact_client.upload(&elf_artifact, elf_bytes).await.expect("failed to upload elf");

    let stdin = Arc::new(stdin);

    let mut opts = SP1CoreOpts::default();
    if let Some(chunk_size) = args.chunk_size {
        opts.minimal_trace_chunk_threshold = chunk_size;
    }
    let task_context = TaskContext { proof_id, parent_id, parent_context, requester_id };
    let global_memory_buffer_size = 2 * args.splice_workers;
    let executor = SP1CoreExecutor::new(
        splicing_engine,
        global_memory_buffer_size,
        elf_artifact,
        stdin,
        common_input_artifact,
        opts,
        0,
        task_context,
        sender,
        artifact_client,
        worker_client,
        None,
        args.cycle_limit,
    );

    let counter_handle = tokio::task::spawn(async move {
        let mut shard_counter = 0;
        while receiver.recv().await.is_some() {
            shard_counter += 1;
        }
        println!("num shards: {shard_counter}");
    });

    // Execute and see the result
    let time = tokio::time::Instant::now();
    let result = executor.execute().await.expect("failed to execute");
    let time = time.elapsed();
    println!(
        "cycles: {}, execution time: {:?}, mhz: {}",
        result.cycles,
        time,
        result.cycles as f64 / (time.as_secs_f64() * 1_000_000.0)
    );

    // Make sure the counter is finished before exiting
    counter_handle.await.expect("counter task panicked");
}

// Executes a program while measuring gas and prints the gas report.
async fn execute_gas(elf: Vec<u8>, stdin: SP1Stdin) {
    let prover = MockProver::new().await;

    let now = std::time::Instant::now();
    let (_, report) = prover
        .execute(Elf::from(elf), stdin)
        .calculate_gas(true)
        .deferred_proof_verification(false)
        .await
        .unwrap();
    let time = now.elapsed();
    println!("gas report: {}", report);
    println!("time: {:?}", time);
    println!(
        "mhz: {}",
        report.total_instruction_count() as f64 / (time.as_secs_f64() * 1_000_000.0)
    );
}

// Executes MinimalExecutor alone
fn execute_minimal(elf: Vec<u8>, stdin: SP1Stdin, trace: bool) {
    let max_trace_size =
        if trace { Some(SP1CoreOpts::default().minimal_trace_chunk_threshold) } else { None };

    let now = std::time::Instant::now();
    let program = Arc::new(Program::from(&elf).expect("parse elf"));
    let mut executor = MinimalExecutor::new(program, false, max_trace_size);
    for buf in stdin.buffer {
        executor.with_input(&buf);
    }
    let time = now.elapsed();
    println!("MinimalExecutor creation time: {:?}", time);

    let now = std::time::Instant::now();
    while executor.execute_chunk().is_some() {}
    let time = now.elapsed();

    println!("exit code: {}, cycles: {}", executor.exit_code(), executor.global_clk());
    println!("execution time: {:?}", time);
    println!("mhz: {}", executor.global_clk() as f64 / (time.as_secs_f64() * 1_000_000.0));
}

pub fn get_program_and_input(program: String, param: String, local: bool) -> (Vec<u8>, SP1Stdin) {
    // When local flag is set, read program and input in local environment.
    if local {
        let program = std::fs::read(&program).unwrap();
        let stdin = std::fs::read(&param).unwrap();
        let stdin: SP1Stdin = bincode::deserialize(&stdin).unwrap();

        return (program, stdin);
    }

    // Otherwise, assume it's a program from the s3 bucket.
    // Download files from S3
    let s3_path = program;
    let output = std::process::Command::new("aws")
        .args(["s3", "cp", &format!("s3://sp1-testing-suite/{s3_path}/program.bin"), "program.bin"])
        .output()
        .unwrap();
    if !output.status.success() {
        panic!("failed to download program.bin");
    }
    let output = if param.is_empty() {
        std::process::Command::new("aws")
            .args(["s3", "cp", &format!("s3://sp1-testing-suite/{s3_path}/stdin.bin"), "stdin.bin"])
            .output()
            .unwrap()
    } else {
        std::process::Command::new("aws")
            .args([
                "s3",
                "cp",
                &format!("s3://sp1-testing-suite/{s3_path}/input/{param}.bin"),
                "stdin.bin",
            ])
            .output()
            .unwrap()
    };
    if !output.status.success() {
        panic!("failed to download stdin.bin");
    }

    let program_path = "program.bin";
    let stdin_path = "stdin.bin";
    let program = std::fs::read(program_path).unwrap();
    let stdin = std::fs::read(stdin_path).unwrap();
    let stdin: SP1Stdin = bincode::deserialize(&stdin).unwrap();

    // remove the files
    std::fs::remove_file(program_path).unwrap();
    std::fs::remove_file(stdin_path).unwrap();

    (program, stdin)
}

#[tokio::main]
#[allow(clippy::field_reassign_with_default)]
async fn main() {
    let args = Args::parse();
    let args_clone = args.clone();

    // Initialize the logger.
    setup_logger();

    // Get the program and input.
    let (elf, stdin) = get_program_and_input(args.program, args.param, args.local);

    match args.mode.as_str() {
        "node" => execute_node(args_clone, elf, stdin).await,
        "gas" => execute_gas(elf, stdin).await,
        "minimal" => execute_minimal(elf, stdin, false),
        "minimal_trace" => execute_minimal(elf, stdin, true),
        _ => panic!("invalid mode"),
    }
}
