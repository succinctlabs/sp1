use succinct_core::{utils, SuccinctProver};

const ED25519_ELF: &[u8] =
    include_bytes!("../../../programs/ed25519/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    std::env::set_var("RUST_LOG", "info");
    utils::setup_logger();
    let prover = SuccinctProver::new();
    prover.run_and_prove(ED25519_ELF);
}
