#![allow(clippy::needless_range_loop)]

use std::{borrow::Borrow, ops::Deref};

use sp1_core_machine::operations::poseidon2::permutation::{
    Poseidon2Cols, Poseidon2Degree3Cols, Poseidon2Degree9Cols,
};

pub mod air;
pub mod columns;
pub mod trace;

/// A chip that implements addition for the opcode Poseidon2Wide.
#[derive(Default, Debug, Clone, Copy)]
pub struct Poseidon2WideChip<const DEGREE: usize>;

impl<'a, const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    /// Transmute a row it to an immutable [`Poseidon2Cols`] instance.
    pub(crate) fn convert<T>(row: impl Deref<Target = [T]>) -> Box<dyn Poseidon2Cols<T> + 'a>
    where
        T: Copy + 'a,
    {
        if DEGREE == 3 {
            let convert: &Poseidon2Degree3Cols<T> = (*row).borrow();
            Box::new(*convert)
        } else if DEGREE == 9 || DEGREE == 17 {
            let convert: &Poseidon2Degree9Cols<T> = (*row).borrow();
            Box::new(*convert)
        } else {
            panic!("Unsupported degree");
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use std::{iter::once, sync::Arc};

    use crate::{
        linear_program, machine::RecursionAir, runtime::instruction as instr,
        stark::BabyBearPoseidon2Outer, MemAccessKind, Runtime,
    };
    use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
    use p3_field::{AbstractField, PrimeField32};
    use p3_symmetric::Permutation;

    use sp1_core_machine::{
        operations::poseidon2::WIDTH,
        utils::{run_test_machine, setup_logger},
    };
    use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, inner_perm, StarkGenericConfig};
    use zkhash::ark_ff::UniformRand;

    #[test]
    fn test_poseidon2() {
        setup_logger();
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type A = RecursionAir<F, 3>;
        type B = RecursionAir<F, 9>;

        let input = [1; WIDTH];
        let output = inner_perm()
            .permute(input.map(BabyBear::from_canonical_u32))
            .map(|x| BabyBear::as_canonical_u32(&x));

        let rng = &mut rand::thread_rng();
        let input_1: [BabyBear; WIDTH] = std::array::from_fn(|_| BabyBear::rand(rng));
        let output_1 = inner_perm().permute(input_1).map(|x| BabyBear::as_canonical_u32(&x));
        let input_1 = input_1.map(|x| BabyBear::as_canonical_u32(&x));

        let instructions =
            (0..WIDTH)
                .map(|i| instr::mem(MemAccessKind::Write, 1, i as u32, input[i]))
                .chain(once(instr::poseidon2(
                    [1; WIDTH],
                    std::array::from_fn(|i| (i + WIDTH) as u32),
                    std::array::from_fn(|i| i as u32),
                )))
                .chain(
                    (0..WIDTH)
                        .map(|i| instr::mem(MemAccessKind::Read, 1, (i + WIDTH) as u32, output[i])),
                )
                .chain((0..WIDTH).map(|i| {
                    instr::mem(MemAccessKind::Write, 1, (2 * WIDTH + i) as u32, input_1[i])
                }))
                .chain(once(instr::poseidon2(
                    [1; WIDTH],
                    std::array::from_fn(|i| (i + 3 * WIDTH) as u32),
                    std::array::from_fn(|i| (i + 2 * WIDTH) as u32),
                )))
                .chain((0..WIDTH).map(|i| {
                    instr::mem(MemAccessKind::Read, 1, (i + 3 * WIDTH) as u32, output_1[i])
                }))
                .collect::<Vec<_>>();

        let program = Arc::new(linear_program(instructions).unwrap());
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new(
            program.clone(),
            BabyBearPoseidon2::new().perm,
        );
        runtime.run().unwrap();

        let config = SC::new();
        let machine_deg_3 = A::compress_machine(config);
        let (pk_3, vk_3) = machine_deg_3.setup(&program);
        let result_deg_3 =
            run_test_machine(vec![runtime.record.clone()], machine_deg_3, pk_3, vk_3);
        if let Err(e) = result_deg_3 {
            panic!("Verification failed: {e:?}");
        }

        let config = SC::new();
        let machine_deg_9 = B::compress_machine(config);
        let (pk_9, vk_9) = machine_deg_9.setup(&program);
        let result_deg_9 = run_test_machine(vec![runtime.record], machine_deg_9, pk_9, vk_9);
        if let Err(e) = result_deg_9 {
            panic!("Verification failed: {e:?}");
        }
    }
}
