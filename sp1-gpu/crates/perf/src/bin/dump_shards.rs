use clap::Parser;
use rand::seq::SliceRandom;
use sp1_core_executor::SP1Context;
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_perf::get_program_and_input;
use sp1_gpu_prover::cuda_worker_builder_with_machine;
use sp1_prover::worker::{SP1LocalNodeBuilder, SP1Proof};
use sp1_prover_types::network_base_types::ProofMode;

#[derive(Parser, Debug)]
#[command(author, version, about = "Dump shard records and vk to S3 for replay benchmarking")]
struct Args {
    /// S3 path for the program (e.g. v6/fibonacci-200m)
    #[arg(long)]
    pub program: String,
    /// Optional param for program input
    #[arg(long, default_value = "")]
    pub param: String,
    /// S3 bucket to upload shard dumps to
    #[arg(long, default_value = "sp1-gpu-shard-dumps")]
    pub bucket: String,
    /// Only upload a random selection of k shards (uploads all if not set)
    #[arg(long)]
    pub k: Option<usize>,
}

#[tokio::main]
#[allow(clippy::print_stdout)]
async fn main() {
    let args = Args::parse();

    dotenv::dotenv().ok();
    sp1_gpu_tracing::init_tracer();

    // Get the program and input.
    let param = args.param.clone();
    let (elf, stdin) = get_program_and_input(args.program.clone(), args.param);

    // Create a temp directory for shard dumps.
    let dump_dir = tempfile::tempdir().expect("failed to create temp dir");
    let dump_path = dump_dir.path().to_path_buf();

    // Set the env var so the prover dumps shards.
    std::env::set_var("SP1_DUMP_SHARD_DIR", dump_path.to_str().unwrap());

    // Run the proving pipeline in core mode.
    let machine = RiscvAir::machine();
    let num_shards = sp1_gpu_cudart::spawn(move |t| async move {
        let worker_builder = cuda_worker_builder_with_machine(t.clone(), machine).await;
        let client =
            SP1LocalNodeBuilder::from_worker_client_builder(worker_builder).build().await.unwrap();

        let context = SP1Context::default();
        tracing::info!("executing the program");
        client.execute(&elf, stdin.clone(), context.clone()).await.unwrap();

        tracing::info!("running setup");
        client.setup(&elf).await.unwrap();

        tracing::info!("proving in core mode to dump shards");
        let proof = client.prove_with_mode(&elf, stdin, context, ProofMode::Core).await.unwrap();

        if let SP1Proof::Core(ref shard_proofs) = &proof.proof {
            shard_proofs.len()
        } else {
            0
        }
    })
    .await
    .unwrap();

    tracing::info!("Proving complete, {num_shards} shards generated");

    // Upload record files to S3.
    let s3_prefix = if param.is_empty() {
        format!("s3://{}/{}/", args.bucket, args.program)
    } else {
        format!("s3://{}/{}/input/{}/", args.bucket, args.program, param)
    };

    // Determine which shard indices to upload.
    let shard_indices: Vec<usize> = if let Some(k) = args.k {
        let mut indices: Vec<usize> = (0..num_shards).collect();
        let mut rng = rand::thread_rng();
        indices.shuffle(&mut rng);
        indices.truncate(k.min(num_shards));
        indices.sort();
        tracing::info!("Randomly selected {}/{num_shards} shards: {indices:?}", indices.len());
        indices
    } else {
        (0..num_shards).collect()
    };

    tracing::info!("Uploading {} shard dumps to {s3_prefix}", shard_indices.len());

    for idx in &shard_indices {
        let filename = format!("record_{idx:04}.bin");
        let src = dump_path.join(&filename);
        let dst = format!("{s3_prefix}{filename}");

        let output = std::process::Command::new("aws")
            .args(["s3", "cp", src.to_str().unwrap(), &dst])
            .output()
            .expect("failed to run aws s3 cp");

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("Failed to upload {filename} to S3: {stderr}");
        }
    }

    // Upload vk.bin at the program level (common to all inputs).
    let vk_src = dump_path.join("vk_0000.bin");
    let vk_dst = format!("s3://{}/{}/vk.bin", args.bucket, args.program);
    tracing::info!("Uploading vk to {vk_dst}");

    let output = std::process::Command::new("aws")
        .args(["s3", "cp", vk_src.to_str().unwrap(), &vk_dst])
        .output()
        .expect("failed to run aws s3 cp");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Failed to upload vk to S3: {stderr}");
    }

    println!("Uploaded shard dumps to {s3_prefix}");
}
