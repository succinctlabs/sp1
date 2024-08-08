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

use alloy_sol_types::SolType;
use clap::Parser;
use common::types::RecordType;
use fibonacci_script::{ProveArgs, PublicValuesTuple};
use operator::{operator_phase1, operator_phase2, prove_begin};
use worker::{worker_phase1, worker_phase2};

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    // Parse the command line arguments.
    let args = ProveArgs::parse();

    // Setup the prover client.
    let (public_values_stream, public_values, mut checkpoints, cycles) =
        prove_begin(args.clone()).unwrap();

    let mut indexed_commitments = Vec::new();
    let num_checkpoints = checkpoints.len();
    for (idx, checkpoint) in checkpoints.iter_mut().enumerate() {
        let is_last_checkpoint = idx == num_checkpoints - 1;
        let result = worker_phase1(
            &args,
            idx as u32,
            checkpoint,
            is_last_checkpoint,
            public_values,
        )
        .unwrap();
        indexed_commitments.push(result);
        tracing::info!("{:?}-th phase1 worker done", idx);
    }

    let challenger = operator_phase1(args.clone(), indexed_commitments.clone()).unwrap();

    let records_vec: Vec<Vec<RecordType>> = indexed_commitments
        .into_iter()
        .map(|(_, pairs)| pairs.into_iter().map(|(_, record)| record).collect())
        .collect();

    let mut shard_proofs_vec = Vec::new();
    for (idx, records) in records_vec.into_iter().enumerate() {
        let shard_proof = worker_phase2(args.clone(), challenger.clone(), records).unwrap();
        shard_proofs_vec.push(shard_proof);
        tracing::info!("{:?}-th phase2 worker done", idx);
    }

    let proof =
        operator_phase2(args.clone(), shard_proofs_vec, public_values_stream, cycles).unwrap();

    if !args.evm {
        let (_, _, fib_n) =
            PublicValuesTuple::abi_decode(proof.public_values.as_slice(), false).unwrap();
        println!("Successfully generated proof!");
        println!("fib(n): {}", fib_n);
    } else {
        // Generate the proof.
        // let proof = client
        //     .prove(&pk, stdin)
        //     .plonk()
        //     .run()
        //     .expect("failed to generate proof");
        // create_plonk_fixture(&proof, &vk);
    }
}
