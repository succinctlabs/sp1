use sp1_sdk::{include_elf, HashableKey, Prover, ProverClient};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const DICE_ELF: &[u8] = include_elf!("dice-game-program");

fn main() {
    let prover = ProverClient::builder().cpu().build();
    let (_, vk) = prover.setup(DICE_ELF);
    println!("Verification Key: {}", vk.bytes32());
}
