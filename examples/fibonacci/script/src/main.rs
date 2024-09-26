use std::sync::Arc;
use clap::Parser;
use sp1_sdk::{ProverClient, SP1Stdin};
use std::time::SystemTime;
use sp1_core_executor::{Executor, ExecutorMode, Program};
use sp1_core_machine::riscv::RiscvAir;
use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig, SP1CoreOpts, CpuProver, MachineProver, MachineRecord};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    #[clap(long, default_value = "20")]
    n: u32,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup fibonacci program
    let program = Program::from(ELF).unwrap();
    let mut runtime = Executor::new(program, SP1CoreOpts::default());

    runtime.executor_mode = ExecutorMode::Trace;

    // Setup the inputs.
    println!("n: {}", args.n);
    let mut stdin = SP1Stdin::new();
    stdin.write(&args.n);

    for input in &stdin.buffer {
        runtime.state.input_stream.push(input.clone());
    }

    let start = SystemTime::now();

    // run to get execution records
    runtime.run().unwrap();


    assert_eq!(
        runtime.records.len(),
        2,
        "We could only test for one record for now and the last is the final one",
    );
    let mut record = runtime.records[0].clone();
    assert!(record.memory_initialize_events.is_empty());
    assert!(record.memory_finalize_events.is_empty());
    runtime.records[1]
        .memory_initialize_events
        .clone_into(&mut record.memory_initialize_events);
    // runtime.records[1].memory_initialize_events = vec![];
    runtime.records[1]
        .memory_finalize_events
        .clone_into(&mut record.memory_finalize_events);
    // runtime.records[1].memory_finalize_events = vec![];
    let program = record.program.clone();
    println!("shard size: {}", runtime.shard_size);
    for rcd in &runtime.records {
        println!("record events: {:?}", rcd.stats());
    }
    println!("final record events: {:?}", record.stats());


    // Setup the prover.
    println!(
        "\n Setup prover (at {} ms)..",
        start.elapsed().unwrap().as_millis()
    );

    let config = BabyBearPoseidon2::new();
    let machine = RiscvAir::machine(config);
    let prover = <CpuProver<_, _>>::new(machine);
    let (pk, vk) = prover.setup(&program);

    // Generate the proof
    println!(
        "\n Generating proof (at {} ms)..",
        start.elapsed().unwrap().as_millis()
    );
    let mut challenger = prover.config().challenger();
    let mut records = vec![record];
    let proof = prover.prove(&pk, records, &mut challenger, SP1CoreOpts::default()).unwrap();


    println!(
        "Successfully generated proof (at {} ms)..",
        start.elapsed().unwrap().as_millis()
    );

    // Verify the proof.
    println!(
        "\n Verifying proof (at {} ms)..",
        start.elapsed().unwrap().as_millis()
    );
    let mut challenger = prover.config().challenger();
    let _ = prover.machine().verify(&vk, &proof, &mut challenger);
    println!("Successfully verified proof!");
}