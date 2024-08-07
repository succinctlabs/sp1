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
use operator::steps::operator_phase2;
use operator::utils::ChallengerState;
use operator::{operator_phase1, prove_begin};
use sp1_core::stark::MachineProver;
use worker::steps::worker_phase2;
use worker::worker_phase1;

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    // Parse the command line arguments.
    let args = ProveArgs::parse();

    // Setup the prover client.
    let serialize_args = bincode::serialize(&args).unwrap();

    let mut public_values_stream = Vec::new();
    let mut public_values = Vec::new();
    let mut checkpoints = Vec::new();
    let mut cycles = 0;
    prove_begin(
        &serialize_args,
        &mut public_values_stream,
        &mut public_values,
        &mut checkpoints,
        &mut cycles,
    );

    let public_values_stream: Vec<u8> =
        bincode::deserialize(public_values_stream.as_slice()).unwrap();

    let mut commitments_vec = Vec::new();
    let mut records_vec = Vec::new();
    let num_checkpoints = checkpoints.len();
    for (idx, checkpoint) in checkpoints.iter_mut().enumerate() {
        let is_last_checkpoint = idx == num_checkpoints - 1;
        let mut commitments = Vec::new();
        let mut records = Vec::new();
        worker_phase1(
            &serialize_args,
            idx as u32,
            checkpoint,
            is_last_checkpoint,
            &public_values,
            &mut commitments,
            &mut records,
        );
        commitments_vec.push(commitments);
        records_vec.push(records);
        tracing::info!("{:?}-th phase1 worker done", idx);
    }

    let mut challenger_state = Vec::new();
    operator_phase1(
        &serialize_args,
        &commitments_vec,
        &records_vec,
        &mut challenger_state,
    );

    let records_vec: Vec<Vec<RecordType>> = records_vec
        .into_iter()
        .map(|record| bincode::deserialize(record.as_slice()).unwrap())
        .collect();

    let (client, _, _, _) = common::init_client(args.clone());
    let challenger = ChallengerState::from_bytes(challenger_state.as_slice())
        .to_challenger(&client.prover.sp1_prover().core_prover.config().perm);
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
