//! A simple script to generate and verify the proof of a given program.

use sp1_core::runtime::Program;
use sp1_core::runtime::Runtime;
use sp1_core::stark::LocalProver;
use sp1_core::stark::RiscvStark;
use sp1_core::stark::VerifyingKey;
use sp1_core::utils;
use sp1_core::utils::BabyBearBlake3;
use sp1_core::utils::StarkUtils;
use sp1_core::SP1Prover;
use sp1_core::SP1Stdin;
use sp1_core::SP1Verifier;

use verifier_script::{get_fixture_proof, simple_program};

const VERIFIER_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // let config = BabyBearBlake3::new();
    // let machine = RiscvStark::new(config);

    // let program = simple_program();
    // let (pk, vk) = machine.setup(&program);

    // let mut runtime = Runtime::new(program);
    // runtime.run();

    // let mut challenger = machine.config().challenger();
    // let proof = machine.prove::<LocalProver<_>>(&pk, runtime.record, &mut challenger);

    // let mut challenger = machine.config().challenger();
    // machine.verify(&vk, &proof, &mut challenger).unwrap();

    utils::setup_logger();

    // Write the first shard proof to stdin of the recursive verifier.
    let mut stdin = SP1Stdin::new();
    let proof = get_fixture_proof().proof;
    stdin.write(&proof);

    // Execute the recursive verifier and get the cycle counts.
    // SP1Prover::execute(VERIFIER_ELF, stdin).expect("execution failed");
    // Generate a recursive proof.
    let proof = SP1Prover::prove(VERIFIER_ELF, stdin).expect("proving failed");
    // Verify the recursive proof.
    SP1Verifier::verify(VERIFIER_ELF, &proof).expect("verification failed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp1_recursion::RISCV_STARK;

    #[test]
    fn test_main_execution() {
        type SC = sp1_recursion::utils::BabyBearBlake3;

        let config = SC::new();
        let mut stdin = SP1Stdin::new();
        let proof = get_fixture_proof().proof;

        let vk = VerifyingKey::empty();
        let mut challenger = config.challenger();
        RISCV_STARK
            .verify(&vk, &proof, &mut challenger)
            .expect("proof verification failed");
    }
}
