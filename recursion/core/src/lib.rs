pub mod air;
pub mod cpu;
pub mod memory;
pub mod poseidon2;
pub mod program;
pub mod runtime;
pub mod stark;

// #[cfg(test)]
// pub mod tests {
//     use crate::air::Block;
//     use crate::runtime::{Instruction, Opcode, Program, Runtime};
//     use crate::stark::RecursionAir;

//     use p3_baby_bear::BabyBear;
//     use p3_field::extension::BinomialExtensionField;
//     use p3_field::{AbstractField, PrimeField32};
//     use sp1_core::lookup::{debug_interactions_with_all_chips, InteractionKind};
//     use sp1_core::stark::{LocalProver, StarkGenericConfig};
//     use sp1_core::utils::BabyBearPoseidon2;
//     use std::time::Instant;

//     type F = BabyBear;
//     type EF = BinomialExtensionField<BabyBear, 4>;

//     pub fn fibonacci_program<F: PrimeField32>() -> Program<F> {
//         // .main
//         //   imm 0(fp) 1 <-- a = 1
//         //   imm 1(fp) 1 <-- b = 1
//         //   imm 2(fp) 10 <-- iterations = 10
//         // .body:
//         //   add 3(fp) 0(fp) 1(fp) <-- tmp = a + b
//         //   sw 0(fp) 1(fp) <-- a = b
//         //   sw 1(fp) 3(fp) <-- b = tmp
//         // . subi 2(fp) 2(fp) 1 <-- iterations -= 1
//         //   bne 2(fp) 0 .body <-- if iterations != 0 goto .body
//         let zero = [F::zero(); 4];
//         let one = [F::one(), F::zero(), F::zero(), F::zero()];
//         Program::<F> {
//             instructions: vec![
//                 // .main
//                 Instruction::new(Opcode::SW, F::zero(), one, zero, true, true),
//                 Instruction::new(Opcode::SW, F::from_canonical_u32(1), one, zero, true, true),
//                 Instruction::new(
//                     Opcode::SW,
//                     F::from_canonical_u32(2),
//                     [F::from_canonical_u32(10), F::zero(), F::zero(), F::zero()],
//                     zero,
//                     true,
//                     true,
//                 ),
//                 // .body:
//                 Instruction::new(
//                     Opcode::ADD,
//                     F::from_canonical_u32(3),
//                     zero,
//                     one,
//                     false,
//                     true,
//                 ),
//                 Instruction::new(Opcode::SW, F::from_canonical_u32(0), one, zero, false, true),
//                 Instruction::new(
//                     Opcode::SW,
//                     F::from_canonical_u32(1),
//                     [F::two() + F::one(), F::zero(), F::zero(), F::zero()],
//                     zero,
//                     false,
//                     true,
//                 ),
//                 Instruction::new(
//                     Opcode::SUB,
//                     F::from_canonical_u32(2),
//                     [F::two(), F::zero(), F::zero(), F::zero()],
//                     one,
//                     false,
//                     true,
//                 ),
//                 Instruction::new(
//                     Opcode::BNE,
//                     F::from_canonical_u32(2),
//                     zero,
//                     [
//                         F::from_canonical_u32(F::ORDER_U32 - 4),
//                         F::zero(),
//                         F::zero(),
//                         F::zero(),
//                     ],
//                     true,
//                     true,
//                 ),
//             ],
//         }
//     }

//     #[test]
//     fn test_fibonacci_execute() {
//         let config = BabyBearPoseidon2::new();
//         let program = fibonacci_program::<F>();
//         let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
//         runtime.run();
//         assert_eq!(
//             runtime.memory[1024 + 1].value,
//             Block::from(BabyBear::from_canonical_u32(144))
//         );
//     }

//     #[test]
//     fn test_fibonacci_prove() {
//         std::env::set_var("RUST_LOG", "debug");
//         sp1_core::utils::setup_logger();

//         type SC = BabyBearPoseidon2;
//         type F = <SC as StarkGenericConfig>::Val;
//         let program = fibonacci_program::<F>();

//         let config = SC::new();

//         let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
//         runtime.run();

//         let machine = RecursionAir::machine(config);
//         let (pk, vk) = machine.setup(&program);
//         let mut challenger = machine.config().challenger();

//         debug_interactions_with_all_chips::<BabyBearPoseidon2, RecursionAir<BabyBear>>(
//             machine.chips(),
//             &runtime.record,
//             vec![InteractionKind::Memory],
//         );

//         let start = Instant::now();
//         let proof = machine.prove::<LocalProver<_, _>>(&pk, runtime.record, &mut challenger);
//         let duration = start.elapsed().as_secs();

//         let mut challenger = machine.config().challenger();
//         machine.verify(&vk, &proof, &mut challenger).unwrap();
//         println!("proving duration = {}", duration);
//     }
// }
