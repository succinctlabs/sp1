// use std::fs::File;
// use std::marker::PhantomData;

// use p3_field::AbstractField;
// use sp1_core::air::MachineAir;
// use sp1_core::stark::RiscvAir;
// use sp1_core::stark::StarkGenericConfig;
// use sp1_core::utils;
// use sp1_core::utils::BabyBearPoseidon2;
// use sp1_core::SP1Prover;
// use sp1_core::SP1Stdin;
// use sp1_recursion_compiler::gnark::GnarkBackend;
// use sp1_recursion_compiler::ir::Builder;
// use sp1_recursion_compiler::ir::{Ext, Felt};
// use sp1_recursion_compiler::verifier::verify_constraints;
// use sp1_recursion_compiler::verifier::StarkGenericBuilderConfig;
// use std::collections::HashMap;
// use std::io::Write;

// fn main() {
//     type SC = BabyBearPoseidon2;
//     type F = <SC as StarkGenericConfig>::Val;
//     type EF = <SC as StarkGenericConfig>::Challenge;

//     // Generate a dummy proof.
//     utils::setup_logger();
//     let elf =
//         include_bytes!("../../../examples/cycle-tracking/program/elf/riscv32im-succinct-zkvm-elf");
//     let proofs = SP1Prover::prove(elf, SP1Stdin::new())
//         .unwrap()
//         .proof
//         .shard_proofs;
//     let proof = &proofs[0];

//     // Extract verification metadata.
//     let machine = RiscvAir::machine(SC::new());
//     let chips = machine
//         .chips()
//         .iter()
//         .filter(|chip| proof.chip_ids.contains(&chip.name()))
//         .collect::<Vec<_>>();
//     let chip = chips[0];
//     let opened_values = &proof.opened_values.chips[0];

//     // Run the verify inside the DSL.
//     let mut builder = Builder::<StarkGenericBuilderConfig<F, SC>>::default();
//     let g: Felt<F> = builder.eval(F::one());
//     let zeta: Ext<F, EF> = builder.eval(F::one());
//     let alpha: Ext<F, EF> = builder.eval(F::one());
//     verify_constraints::<F, SC, _>(&mut builder, chip, opened_values, g, zeta, alpha);

//     // Emit the constraints using the Gnark backend.
//     let mut backend = GnarkBackend::<StarkGenericBuilderConfig<F, BabyBearPoseidon2>> {
//         nb_backend_vars: 0,
//         used: HashMap::new(),
//         phantom: PhantomData,
//     };
//     let result = backend.compile(builder.operations);
//     let manifest_dir = env!("CARGO_MANIFEST_DIR");
//     let path = format!("{}/src/gnark/lib/main.go", manifest_dir);
//     let mut file = File::create(path).unwrap();
//     file.write_all(result.as_bytes()).unwrap();
// }

fn main() {}
