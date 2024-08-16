//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be verified
//! on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --package fibonacci-script --bin prove --release
//! ```

use clap::Parser;
use fibonacci_script::FibonacciArgs;
use sp1_sdk::mmp::{common::ProveArgs, scenario};

pub const FIBONACCI_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    // Parse the command line arguments.
    let fibonacci_args = FibonacciArgs::parse();

    let args = ProveArgs {
        zkvm_input: fibonacci_args.n.to_le_bytes().to_vec(),
        elf: FIBONACCI_ELF.to_vec(),
    };

    let (core_proof, _, plonk_proof) = scenario::plonk_prove::mpc_prove_plonk(&args).unwrap();
    let _ = scenario::plonk_prove::scenario_end(&args, &core_proof, &plonk_proof);
}
