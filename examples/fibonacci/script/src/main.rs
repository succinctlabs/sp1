use clap::Parser;
use sp1_sdk::{ProverClient, SP1Stdin};
use std::time::SystemTime;
use sp1_core_executor::{Executor, ExecutorMode, Program};
use sp1_core_machine::riscv::RiscvAir;
use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig, SP1CoreOpts, CpuProver, MachineProver};

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
    let start = SystemTime::now();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup fibonacci program
    let program = Program::from(ELF).unwrap();
    // println!("program: {:?}", program);
    let mut runtime = Executor::new(program, SP1CoreOpts::default());

    runtime.executor_mode = ExecutorMode::Trace;

    // Setup the inputs.
    println!("n: {}", args.n);
    let mut stdin = SP1Stdin::new();
    stdin.write(&args.n);

    for input in &stdin.buffer {
        runtime.state.input_stream.push(input.clone());
    }

    // run to get execution records
    runtime.run().unwrap();


    // Setup the prover.
    println!(
        "\n Setup prover (at {} sec)..",
        start.elapsed().unwrap().as_secs()
    );

    let config = BabyBearPoseidon2::new();
    let machine = RiscvAir::machine(config);
    let prover = <CpuProver<_, _>>::new(machine);
    let (pk, vk) = prover.setup(runtime.program.as_ref());

    // Generate the proof
    println!(
        "\n Generating proof (at {} sec)..",
        start.elapsed().unwrap().as_secs()
    );
    let mut challenger = prover.config().challenger();
    //let records = vec![runtime.record];
    let records = runtime.records;
    let proof = prover.prove(&pk, records, &mut challenger, SP1CoreOpts::default()).unwrap();


    println!("Successfully generated proof!");

    // Verify the proof.
    println!(
        "\n Verifying proof (at {} sec)..",
        start.elapsed().unwrap().as_secs()
    );
    let mut challenger = prover.config().challenger();
    let _ = prover.machine().verify(&vk, &proof, &mut challenger);
    println!("Successfully verified proof!");
}