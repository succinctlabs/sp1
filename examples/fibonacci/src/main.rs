use succinct_core::{utils, SuccinctProver};

const FIBONACCI_ELF: &[u8] =
    include_bytes!("../../../programs/fibonacci/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    utils::setup_logger();
    let prover = SuccinctProver::new();
    prover.prove(FIBONACCI_ELF);
}
