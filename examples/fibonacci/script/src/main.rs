//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be verified
//! on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --package fibonacci-script --bin prove --release
//! ```

pub mod common;
pub mod operator;
pub mod worker;

use clap::Parser;
use fibonacci_script::{scenario, ProveArgs};

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    // Parse the command line arguments.
    let args = ProveArgs::parse();

    let (core_proof, _, plonk_proof) =
        scenario::plonk_prove::mpc_prove_plonk(args.clone()).unwrap();
    scenario::plonk_prove::scenario_end(args, &core_proof, &plonk_proof)
}
