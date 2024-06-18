#![allow(clippy::needless_range_loop)]

use std::borrow::Borrow;
use std::ops::Deref;

use p3_baby_bear::{MONTY_INVERSE, POSEIDON2_INTERNAL_MATRIX_DIAG_16_BABYBEAR_MONTY};
use p3_field::AbstractField;
use p3_field::PrimeField32;

pub mod air;
pub mod columns;
pub mod events;
pub mod trace;

use p3_poseidon2::matmul_internal;

use self::columns::Poseidon2;
use self::columns::Poseidon2Degree3;
use self::columns::Poseidon2Degree9;

/// The width of the permutation.
pub const WIDTH: usize = 16;
pub const RATE: usize = WIDTH / 2;

pub const NUM_EXTERNAL_ROUNDS: usize = 8;
pub const NUM_INTERNAL_ROUNDS: usize = 13;
pub const NUM_ROUNDS: usize = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS;

/// A chip that implements addition for the opcode ADD.
#[derive(Default)]
pub struct Poseidon2WideChip<const DEGREE: usize, const ROUND_CHUNK_SIZE: usize> {
    pub fixed_log2_rows: Option<usize>,
    pub pad: bool,
}

impl<'a, const DEGREE: usize, const ROUND_CHUNK_SIZE: usize>
    Poseidon2WideChip<DEGREE, ROUND_CHUNK_SIZE>
{
    pub(crate) fn convert<T>(row: impl Deref<Target = [T]>) -> Box<dyn Poseidon2<'a, T> + 'a>
    where
        T: Copy + 'a,
    {
        if DEGREE == 3 {
            let convert: &Poseidon2Degree3<T> = (*row).borrow();
            Box::new(*convert)
        } else if DEGREE == 9 {
            let convert: &Poseidon2Degree9<T> = (*row).borrow();
            Box::new(*convert)
        } else {
            panic!("Unsupported degree");
        }
    }
}

pub fn apply_m_4<AF>(x: &mut [AF])
where
    AF: AbstractField,
{
    let t01 = x[0].clone() + x[1].clone();
    let t23 = x[2].clone() + x[3].clone();
    let t0123 = t01.clone() + t23.clone();
    let t01123 = t0123.clone() + x[1].clone();
    let t01233 = t0123.clone() + x[3].clone();
    // The order here is important. Need to overwrite x[0] and x[2] after x[1] and x[3].
    x[3] = t01233.clone() + x[0].double(); // 3*x[0] + x[1] + x[2] + 2*x[3]
    x[1] = t01123.clone() + x[2].double(); // x[0] + 2*x[1] + 3*x[2] + x[3]
    x[0] = t01123 + t01; // 2*x[0] + 3*x[1] + x[2] + x[3]
    x[2] = t01233 + t23; // x[0] + x[1] + 2*x[2] + 3*x[3]
}

pub(crate) fn external_linear_layer<AF: AbstractField>(state: &mut [AF; WIDTH]) {
    for j in (0..WIDTH).step_by(4) {
        apply_m_4(&mut state[j..j + 4]);
    }
    let sums: [AF; 4] = core::array::from_fn(|k| {
        (0..WIDTH)
            .step_by(4)
            .map(|j| state[j + k].clone())
            .sum::<AF>()
    });

    for j in 0..WIDTH {
        state[j] += sums[j % 4].clone();
    }
}

pub(crate) fn internal_linear_layer<F: AbstractField>(state: &mut [F; WIDTH]) {
    let matmul_constants: [<F as AbstractField>::F; WIDTH] =
        POSEIDON2_INTERNAL_MATRIX_DIAG_16_BABYBEAR_MONTY
            .iter()
            .map(|x| <F as AbstractField>::F::from_wrapped_u32(x.as_canonical_u32()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    matmul_internal(state, matmul_constants);
    let monty_inverse = F::from_wrapped_u32(MONTY_INVERSE.as_canonical_u32());
    state.iter_mut().for_each(|i| *i *= monty_inverse.clone());
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use crate::runtime::ExecutionRecord;
    use itertools::Itertools;
    use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
    use p3_symmetric::Permutation;
    use sp1_core::air::MachineAir;
    use sp1_core::stark::StarkGenericConfig;
    use sp1_core::utils::{inner_perm, uni_stark_prove, uni_stark_verify, BabyBearPoseidon2};
    use zkhash::ark_ff::UniformRand;

    use super::events::Poseidon2CompressEvent;
    use super::{Poseidon2WideChip, WIDTH};

    fn generate_trace_degree<const DEGREE: usize, const ROUND_CHUNK_SIZE: usize>() {
        let chip = Poseidon2WideChip::<DEGREE, ROUND_CHUNK_SIZE> {
            fixed_log2_rows: None,
            pad: true,
        };

        let test_inputs = vec![
            [BabyBear::from_canonical_u32(1); WIDTH],
            [BabyBear::from_canonical_u32(2); WIDTH],
            [BabyBear::from_canonical_u32(3); WIDTH],
            [BabyBear::from_canonical_u32(4); WIDTH],
        ];

        let gt: Poseidon2<
            BabyBear,
            Poseidon2ExternalMatrixGeneral,
            DiffusionMatrixBabyBear,
            16,
            7,
        > = inner_perm();

        let expected_outputs = test_inputs
            .iter()
            .map(|input| gt.permute(*input))
            .collect::<Vec<_>>();

        let mut input_exec = ExecutionRecord::<BabyBear>::default();
        for (input, output) in test_inputs.clone().into_iter().zip_eq(expected_outputs) {
            input_exec
                .poseidon2_compress_events
                .push(Poseidon2CompressEvent::dummy_from_input(input, output));
        }

        // Generate trace will assert for the expected outputs.
        chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());
    }

    /// A test generating a trace for a single permutation that checks that the output is correct
    #[test]
    fn generate_trace() {
        generate_trace_degree::<3, 1>();
        generate_trace_degree::<9, 1>();
    }

    fn poseidon2_wide_prove_babybear_degree<const DEGREE: usize, const ROUND_CHUNK_SIZE: usize>(
        inputs: Vec<[BabyBear; 16]>,
        outputs: Vec<[BabyBear; 16]>,
    ) {
        let chip = Poseidon2WideChip::<DEGREE, ROUND_CHUNK_SIZE> {
            fixed_log2_rows: None,
            pad: true,
        };
        let mut input_exec = ExecutionRecord::<BabyBear>::default();
        for (input, output) in inputs.into_iter().zip_eq(outputs) {
            input_exec
                .poseidon2_compress_events
                .push(Poseidon2CompressEvent::dummy_from_input(input, output));
        }
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());

        let config = BabyBearPoseidon2::compressed();
        let mut challenger = config.challenger();

        let start = Instant::now();
        let proof = uni_stark_prove(&config, &chip, &mut challenger, trace);
        let duration = start.elapsed().as_secs_f64();
        println!("proof duration = {:?}", duration);

        let mut challenger = config.challenger();
        let start = Instant::now();
        uni_stark_verify(&config, &chip, &mut challenger, &proof)
            .expect("expected proof to be valid");

        let duration = start.elapsed().as_secs_f64();
        println!("verify duration = {:?}", duration);
    }

    #[test]
    fn poseidon2_wide_prove_babybear_success() {
        let rng = &mut rand::thread_rng();

        let test_inputs: Vec<[BabyBear; 16]> = (0..1000)
            .map(|_| core::array::from_fn(|_| BabyBear::rand(rng)))
            .collect_vec();

        let gt: Poseidon2<
            BabyBear,
            Poseidon2ExternalMatrixGeneral,
            DiffusionMatrixBabyBear,
            16,
            7,
        > = inner_perm();

        let expected_outputs = test_inputs
            .iter()
            .map(|input| gt.permute(*input))
            .collect::<Vec<_>>();

        poseidon2_wide_prove_babybear_degree::<3, 1>(test_inputs.clone(), expected_outputs.clone());
        poseidon2_wide_prove_babybear_degree::<9, 1>(test_inputs, expected_outputs);
    }

    #[test]
    #[should_panic]
    fn poseidon2_wide_prove_babybear_failure() {
        let rng = &mut rand::thread_rng();

        let test_inputs = (0..1000)
            .map(|i| [BabyBear::from_canonical_u32(i); WIDTH])
            .collect_vec();

        let bad_outputs: Vec<[BabyBear; 16]> = (0..1000)
            .map(|_| core::array::from_fn(|_| BabyBear::rand(rng)))
            .collect_vec();

        poseidon2_wide_prove_babybear_degree::<3, 1>(test_inputs.clone(), bad_outputs.clone());
        poseidon2_wide_prove_babybear_degree::<9, 1>(test_inputs, bad_outputs);
    }
}
