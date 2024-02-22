use serde::{Deserialize, Serialize};
use sp1_core::{
    runtime::{Program, Runtime},
    utils, SP1Prover, SP1Stdin, SP1Verifier,
};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(C)]
struct MyPointUnaligned {
    pub x: u32,
    pub y: u32,
    pub b: bool,
    pub test: [u8; 1200],
}

fn main() {
    // Setup a tracer for logging.
    utils::setup_logger();

    // Create an input stream.
    let mut stdin = SP1Stdin::new();
    let p = MyPointUnaligned {
        x: 1,
        y: 2,
        b: true,
        test: [2; 1200],
    };
    let q = MyPointUnaligned {
        x: 3,
        y: 4,
        b: false,
        test: [1; 1200],
    };

    let program = Program::from(ELF);
    let mut runtime = Runtime::new(program);
    // runtime.write_stdin_slice(&stdin.buffer.data);
    runtime.write_magic(p);
    runtime.write_magic(q);
    runtime.run();

    println!("cpu cycles: {}", runtime.state.global_clk);
    // Ok(SP1Stdout::from(&runtime.state.output_stream))

    // stdin.write(&p);
    // stdin.write(&q);

    // Generate the proof for the given program.
    // let mut proof = SP1Prover::prove(ELF, stdin).expect("proving failed");

    // // Read the output.
    // let r = proof.stdout.read::<MyPointUnaligned>();
    // println!("r: {:?}", r);

    // // Verify proof.
    // SP1Verifier::verify(ELF, &proof).expect("verification failed");

    // // Save the proof.
    // proof
    //     .save("proof-with-pis.json")
    //     .expect("saving proof failed");

    // println!("succesfully generated and verified proof for the program!")
}
