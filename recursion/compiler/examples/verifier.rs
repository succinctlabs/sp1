use p3_field::AbstractField;
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
use sp1_recursion_compiler::ir::{Ext, Felt};
use sp1_recursion_core::runtime::Runtime;

fn main() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    let mut rng = thread_rng();

    // Generate a dummy proof.
    utils::setup_logger();
    let elf =
        include_bytes!("../../../examples/cycle-tracking/program/elf/riscv32im-succinct-zkvm-elf");
    let proofs = SP1Prover::prove(elf, SP1Stdin::new())
        .unwrap()
        .proof
        .shard_proofs;
    let proof = &proofs[0];

    // Extract verification metadata.
    let machine = RiscvAir::machine(SC::new());
    let chips = machine
        .chips()
        .iter()
        .filter(|chip| proof.chip_ids.contains(&chip.name()))
        .collect::<Vec<_>>();
    let chip = chips[0];
    let opened_values = &proof.opened_values.chips[0];

    // Run the verify inside the DSL.
    let mut builder = VmBuilder::<F, EF>::default();
    let g: Felt<F> = builder.eval(F::one());
    let zeta: Ext<F, EF> = builder.eval(rng.gen::<F>());
    let alpha: Ext<F, EF> = builder.eval(rng.gen::<F>());
    builder.verify_constraints::<SC, _>(chip, opened_values, g, zeta, alpha);

    let code = builder.compile_to_asm();
    println!("{}", code);

    let program = code.machine_code();
    println!("Program size = {}", program.instructions.len());

    let mut runtime = Runtime::<F, EF>::new(&program);
    runtime.run();
}
