use std::fs;
use std::process::exit;

use succinct_core::runtime::Program;
use succinct_core::runtime::Runtime;
use succinct_core::stark::prover::LocalProver;
use succinct_core::stark::SegmentProof;
use succinct_core::utils::BabyBearPoseidon2;
use succinct_core::utils::StarkUtils;

// This program should be run from the top level of the verifier-zkvm package.  The pathnames
// below assume that.
fn main() {
    let program = Program::from_elf("../../programs/fibonacci/elf/riscv32im-succinct-zkvm-elf");

    let mut runtime = Runtime::new(program);
    runtime.run();

    let config = BabyBearPoseidon2::new();
    let mut challenger = config.challenger();

    // Prove the program.
    let (segment_proofs, global_proof) =
        runtime.prove::<_, _, BabyBearPoseidon2, LocalProver<_>>(&config, &mut challenger);

    // Check to see if the proofs directory already exists
    let directory_name = "data/proofs";

    match fs::metadata(directory_name) {
        Ok(metadata) => {
            // Check if the metadata represents a directory
            if !metadata.is_dir() {
                log::error!("{} exists, but it is not a directory.", directory_name);
                exit(1);
            }
        }
        Err(_) => {
            // If the directory does not exist, create it
            match fs::create_dir(directory_name) {
                Ok(_) => (),
                Err(e) => {
                    log::error!("Error creating directory: {}", e);
                    exit(1);
                }
            }
        }
    }

    // Create the segment proofs file
    let segment_proofs_file_name = format!("{}/segment_proofs.bytes", directory_name);
    let segment_proofs_bytes = bincode::serialize(&segment_proofs).unwrap();
    let _decoded_test: Vec<SegmentProof<BabyBearPoseidon2>> =
        bincode::deserialize(&segment_proofs_bytes[..]).unwrap();
    match fs::write(segment_proofs_file_name, segment_proofs_bytes) {
        Ok(_) => (),
        Err(e) => {
            log::error!("Error writing segment proofs file: {}", e);
            exit(1);
        }
    }

    // Save the global proof
    let global_proof_file_name = format!("{}/global_proof.bytes", directory_name);
    let global_proof_bytes = bincode::serialize(&global_proof).unwrap();
    let _decoded_test: SegmentProof<BabyBearPoseidon2> =
        bincode::deserialize(&global_proof_bytes[..]).unwrap();
    match fs::write(global_proof_file_name, global_proof_bytes) {
        Ok(_) => (),
        Err(e) => {
            log::error!("Error writing global proof file: {}", e);
            exit(1);
        }
    }

    // Verify the proof.
    let mut challenger = config.challenger();
    runtime
        .verify::<_, _, BabyBearPoseidon2>(&config, &mut challenger, &segment_proofs, &global_proof)
        .unwrap();
}
