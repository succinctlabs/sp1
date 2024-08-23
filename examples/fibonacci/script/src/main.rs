use sp1_sdk::{utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    use sp1_prover::components::DefaultProverComponents;
    use sp1_sdk::utils::setup_logger;
    use sp1_sdk::SP1Stdin;

    setup_logger();
    let prover = sp1_prover::SP1Prover::<DefaultProverComponents>::new();

    let elf: Vec<u8> = bincode::deserialize(include_bytes!("elf")).unwrap();
    let stdin: SP1Stdin = bincode::deserialize(include_bytes!("stdin")).unwrap();

    let sdk_prover = ProverClient::new();
    let (pk, vk) = sdk_prover.setup(&elf);
    let proof = sdk_prover.prove(&pk, stdin).run().unwrap();
    sdk_prover.verify(&proof, &vk).expect("failed to verify");
}
