use curta_core::{CurtaProver, CurtaStdin, CurtaVerifier};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-curta-zkvm-elf");

fn main() {
    let mut stdin = CurtaStdin::new();

    // FEN representation of a chessboard in its initial state
    let fen = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1".to_string();
    // SAN representation Queen's pawn opening
    let san = "d4".to_string();

    stdin.write(&fen);
    stdin.write(&san);
    
    let mut proof = CurtaProver::prove(ELF, stdin).expect("proving failed");

    // Read output.
    let is_valid_move = proof.stdout.read::<bool>();

    println!("is_valid_move: {}", is_valid_move);

    // Verify proof.
    CurtaVerifier::verify(ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
