use sp1_core::runtime::{Program, Runtime};
use sp1_sdk::{ProverClient, SP1Stdin};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    let mut stdin = SP1Stdin::new();

    // FEN representation of a chessboard in its initial state
    let fen = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1".to_string();
    stdin.write(&fen);

    // SAN representation Queen's pawn opening
    let san = "d4".to_string();
    stdin.write(&san);

    println!("stdin: {:?}", stdin.buffer);

    let flat_stdin = stdin
        .buffer
        .iter()
        .flat_map(|v| v.iter())
        .copied()
        .collect::<Vec<u8>>();
    println!("flat_stdin: {:?}", flat_stdin);
    println!("flat_stdin.len(): {}", flat_stdin.len());

    let program = Program::from(ELF);
    let mut runtime = Runtime::new(program);
    runtime.write_vecs(&stdin.buffer);
    // runtime.write_stdin_slice(&flat_stdin);
    runtime.run();

    let client = ProverClient::new();
    let mut proof = client.prove(ELF, stdin).unwrap();

    // Read output.
    let is_valid_move = proof.public_values.read::<bool>();
    println!("is_valid_move: {}", is_valid_move);

    // Verify proof.
    client.verify(ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
