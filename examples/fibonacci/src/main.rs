use succinct_core::{utils, SuccinctProver};

const FIBONACCI_ELF: &[u8] =
    include_bytes!("../../../programs/ed25519/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    std::env::set_var("RUST_TRACER", "info");
    // utils::setup_logger();
    utils::setup_tracer();
    let prover = SuccinctProver::new();
    prover.prove(FIBONACCI_ELF);
}
