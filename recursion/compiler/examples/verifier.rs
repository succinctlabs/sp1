use p3_field::AbstractField;
use p3_field::PrimeField32;
use rand::thread_rng;
use rand::Rng;
use sp1_core::air::MachineAir;
use sp1_core::stark::RiscvAir;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_core::SP1Prover;
use sp1_core::SP1Stdin;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_core::runtime::Runtime;

fn main() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    let mut rng = thread_rng();

    // Generate a dummy proof.
    utils::setup_logger();
    let elf = include_bytes!("../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    let proofs = SP1Prover::prove(elf, SP1Stdin::new())
        .unwrap()
        .proof
        .shard_proofs;

    println!("Proof generated successfully");

    // Extract verification metadata.
    let machine = RiscvAir::machine(SC::new());

    // Run the verify inside the DSL.
    let mut builder = VmBuilder::<F, EF>::default();
    let g_val = F::one();

    let zeta_val = rng.gen::<EF>();
    let alpha_val = rng.gen::<EF>();

    for shard_proof in proofs.into_iter().take(1) {
        let chips = machine
            .chips()
            .iter()
            .filter(|chip| shard_proof.chip_ids.contains(&chip.name()))
            .collect::<Vec<_>>();
        for (chip, values) in chips
            .into_iter()
            .zip(shard_proof.opened_values.chips.iter())
        {
            builder.eval_constraints_test::<SC, _>(chip, values, g_val, zeta_val, alpha_val)
        }
    }

    let program = builder.compile();

    let mut runtime = Runtime::<F, EF>::new(&program);
    runtime.run();
    println!(
        "The program executed successfully, number of cycles: {}",
        runtime.clk.as_canonical_u32() / 4
    );
}
