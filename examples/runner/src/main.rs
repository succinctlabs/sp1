use succinct_core::SuccinctProver;

const FIBONACCI_ELF: &[u8] = include_bytes!("../../fibonacci/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    let prover = SuccinctProver::new();
    prover.prove_elf(FIBONACCI_ELF);
}
