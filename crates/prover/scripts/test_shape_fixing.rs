#![allow(clippy::print_stdout)]

use clap::Parser;
use p3_baby_bear::BabyBear;
use p3_util::log2_ceil_usize;
use sp1_core_executor::{Executor, Program, RiscvAirId, SP1Context};
use sp1_core_machine::{
    io::SP1Stdin, riscv::RiscvAir, shape::CoreShapeConfig, utils::setup_logger,
};
use sp1_stark::SP1CoreOpts;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, value_delimiter = ' ')]
    list: Vec<String>,
    #[arg(short, long, value_delimiter = ' ')]
    shard_size: usize,
}

fn test_shape_fixing(
    elf: &[u8],
    stdin: &SP1Stdin,
    opts: SP1CoreOpts,
    context: SP1Context,
    shape_config: &CoreShapeConfig<BabyBear>,
) {
    // Setup the program.
    let mut program = Program::from(elf).unwrap();
    shape_config.fix_preprocessed_shape(&mut program).unwrap();

    // Setup the executor.
    let mut executor = Executor::with_context(program, opts, context);
    executor.maximal_shapes = Some(
        shape_config.maximal_core_shapes(log2_ceil_usize(opts.shard_size)).into_iter().collect(),
    );
    executor.write_vecs(&stdin.buffer);
    for (proof, vkey) in stdin.proofs.iter() {
        executor.write_proof(proof.clone(), vkey.clone());
    }

    // Collect the maximal shapes.
    let mut finished = false;
    while !finished {
        let (records, f) = executor.execute_record(true).unwrap();
        finished = f;
        for mut record in records {
            let _ = record.defer();
            let heights = RiscvAir::<BabyBear>::core_heights(&record);
            println!("heights: {heights:?}");

            shape_config.fix_shape(&mut record).unwrap();

            if record.contains_cpu() &&
                record.shape.unwrap().height(&RiscvAirId::Cpu).unwrap() > opts.shard_size
            {
                panic!("something went wrong")
            }
        }
    }
}

fn main() {
    // Setup logger.
    setup_logger();

    // Parse arguments.
    let args = Args::parse();

    // Setup the options.
    let config = CoreShapeConfig::<BabyBear>::default();
    let mut opts = SP1CoreOpts { shard_batch_size: 1, ..Default::default() };
    opts.shard_size = 1 << args.shard_size;

    // For each program, collect the maximal shapes.
    let program_list = args.list;
    for s3_path in program_list {
        // Download program and stdin files from S3.
        tracing::info!("download elf and input for {}", s3_path);

        // Download program.bin.
        let status = std::process::Command::new("aws")
            .args([
                "s3",
                "cp",
                &format!("s3://sp1-testing-suite/{s3_path}/program.bin"),
                "program.bin",
            ])
            .status()
            .expect("Failed to execute aws s3 cp command for program.bin");
        if !status.success() {
            panic!("Failed to download program.bin from S3");
        }

        // Download stdin.bin.
        let status = std::process::Command::new("aws")
            .args(["s3", "cp", &format!("s3://sp1-testing-suite/{s3_path}/stdin.bin"), "stdin.bin"])
            .status()
            .expect("Failed to execute aws s3 cp command for stdin.bin");
        if !status.success() {
            panic!("Failed to download stdin.bin from S3");
        }

        // Read the program and stdin.
        let elf = std::fs::read("program.bin").expect("failed to read program");
        let stdin = std::fs::read("stdin.bin").expect("failed to read stdin");
        let stdin: SP1Stdin = bincode::deserialize(&stdin).expect("failed to deserialize stdin");

        // Collect the maximal shapes for each shard size.
        let elf = elf.clone();
        let stdin = stdin.clone();
        let new_context = SP1Context::default();
        test_shape_fixing(&elf, &stdin, opts, new_context, &config);

        std::fs::remove_file("program.bin").expect("failed to remove program.bin");
        std::fs::remove_file("stdin.bin").expect("failed to remove stdin.bin");
    }
}
