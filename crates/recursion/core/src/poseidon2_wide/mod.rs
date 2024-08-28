#![allow(clippy::needless_range_loop)]

use std::{
    borrow::{Borrow, BorrowMut},
    ops::Deref,
};

use p3_baby_bear::{MONTY_INVERSE, POSEIDON2_INTERNAL_MATRIX_DIAG_16_BABYBEAR_MONTY};
use p3_field::{AbstractField, PrimeField32};

pub mod air;
pub mod columns;
pub mod events;
pub mod trace;

use p3_poseidon2::matmul_internal;

use self::columns::{Poseidon2, Poseidon2Degree3, Poseidon2Degree9, Poseidon2Mut};

/// The width of the permutation.
pub const WIDTH: usize = 16;
pub const RATE: usize = WIDTH / 2;

pub const NUM_EXTERNAL_ROUNDS: usize = 8;
pub const NUM_INTERNAL_ROUNDS: usize = 13;
pub const NUM_ROUNDS: usize = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS;

/// A chip that implements addition for the opcode ADD.
#[derive(Default)]
pub struct Poseidon2WideChip<const DEGREE: usize> {
    pub fixed_log2_rows: Option<usize>,
    pub pad: bool,
}

impl<'a, const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    /// Transmute a row it to an immutable Poseidon2 instance.
    pub(crate) fn convert<T>(row: impl Deref<Target = [T]>) -> Box<dyn Poseidon2<'a, T> + 'a>
    where
        T: Copy + 'a,
    {
        if DEGREE == 3 {
            let convert: &Poseidon2Degree3<T> = (*row).borrow();
            Box::new(*convert)
        } else if DEGREE == 9 || DEGREE == 17 {
            let convert: &Poseidon2Degree9<T> = (*row).borrow();
            Box::new(*convert)
        } else {
            panic!("Unsupported degree");
        }
    }

    /// Transmute a row it to a mutable Poseidon2 instance.
    pub(crate) fn convert_mut<'b: 'a, F: PrimeField32>(
        &self,
        row: &'b mut [F],
    ) -> Box<dyn Poseidon2Mut<'a, F> + 'a> {
        if DEGREE == 3 {
            let convert: &mut Poseidon2Degree3<F> = row.borrow_mut();
            Box::new(convert)
        } else if DEGREE == 9 || DEGREE == 17 {
            let convert: &mut Poseidon2Degree9<F> = row.borrow_mut();
            Box::new(convert)
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
    let sums: [AF; 4] =
        core::array::from_fn(|k| (0..WIDTH).step_by(4).map(|j| state[j + k].clone()).sum::<AF>());

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
pub(crate) mod tests {
    use std::{array, time::Instant};

    use crate::{
        air::Block,
        memory::MemoryRecord,
        poseidon2_wide::events::Poseidon2HashEvent,
        runtime::{ExecutionRecord, DIGEST_SIZE},
    };
    use itertools::Itertools;
    use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
    use p3_symmetric::Permutation;
    use rand::random;

    use sp1_core_machine::utils::{uni_stark_prove, uni_stark_verify};
    use sp1_stark::{
        air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, inner_perm, StarkGenericConfig,
    };
    use zkhash::ark_ff::UniformRand;

    use super::{
        events::{Poseidon2AbsorbEvent, Poseidon2CompressEvent, Poseidon2FinalizeEvent},
        Poseidon2WideChip, WIDTH,
    };

    fn poseidon2_wide_prove_babybear_degree<const DEGREE: usize>(
        input_exec: ExecutionRecord<BabyBear>,
    ) {
        let chip = Poseidon2WideChip::<DEGREE> { fixed_log2_rows: None, pad: true };

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

    fn dummy_memory_access_records(
        memory_values: Vec<BabyBear>,
        prev_ts: BabyBear,
        ts: BabyBear,
    ) -> Vec<MemoryRecord<BabyBear>> {
        memory_values
            .iter()
            .map(|value| MemoryRecord::new_read(BabyBear::zero(), Block::from(*value), ts, prev_ts))
            .collect_vec()
    }

    pub(crate) fn generate_test_execution_record(
        incorrect_trace: bool,
    ) -> ExecutionRecord<BabyBear> {
        const NUM_ABSORBS: usize = 1000;
        const NUM_COMPRESSES: usize = 1000;

        let mut input_exec = ExecutionRecord::<BabyBear>::default();

        let rng = &mut rand::thread_rng();
        let permuter: Poseidon2<
            BabyBear,
            Poseidon2ExternalMatrixGeneral,
            DiffusionMatrixBabyBear,
            16,
            7,
        > = inner_perm();

        // Generate hash test events.
        let hash_test_input_sizes: [usize; NUM_ABSORBS] =
            array::from_fn(|_| random::<usize>() % 128 + 1);
        hash_test_input_sizes.iter().enumerate().for_each(|(i, input_size)| {
            let test_input = (0..*input_size).map(|_| BabyBear::rand(rng)).collect_vec();

            let prev_ts = BabyBear::from_canonical_usize(i);
            let absorb_ts = BabyBear::from_canonical_usize(i + 1);
            let finalize_ts = BabyBear::from_canonical_usize(i + 2);
            let hash_num = i as u32;
            let absorb_num = 0_u32;
            let hash_and_absorb_num =
                BabyBear::from_canonical_u32(hash_num * (1 << 12) + absorb_num);
            let start_addr = BabyBear::from_canonical_usize(i + 1);
            let input_len = BabyBear::from_canonical_usize(*input_size);

            let mut absorb_event = Poseidon2AbsorbEvent::new(
                absorb_ts,
                hash_and_absorb_num,
                start_addr,
                input_len,
                BabyBear::from_canonical_u32(hash_num),
                BabyBear::from_canonical_u32(absorb_num),
            );

            let mut hash_state = [BabyBear::zero(); WIDTH];
            let mut hash_state_cursor = 0;
            absorb_event.populate_iterations(
                start_addr,
                input_len,
                &dummy_memory_access_records(test_input.clone(), prev_ts, absorb_ts),
                &permuter,
                &mut hash_state,
                &mut hash_state_cursor,
            );

            input_exec.poseidon2_hash_events.push(Poseidon2HashEvent::Absorb(absorb_event));

            let do_perm = hash_state_cursor != 0;
            let mut perm_output = permuter.permute(hash_state);
            if incorrect_trace {
                perm_output = [BabyBear::rand(rng); WIDTH];
            }

            let state = if do_perm { perm_output } else { hash_state };

            input_exec.poseidon2_hash_events.push(Poseidon2HashEvent::Finalize(
                Poseidon2FinalizeEvent {
                    clk: finalize_ts,
                    hash_num: BabyBear::from_canonical_u32(hash_num),
                    output_ptr: start_addr,
                    output_records: dummy_memory_access_records(
                        state.as_slice().to_vec(),
                        absorb_ts,
                        finalize_ts,
                    )[0..DIGEST_SIZE]
                        .try_into()
                        .unwrap(),
                    state_cursor: hash_state_cursor,
                    perm_input: hash_state,
                    perm_output,
                    previous_state: hash_state,
                    state,
                    do_perm,
                },
            ));
        });

        let compress_test_inputs: Vec<[BabyBear; WIDTH]> = (0..NUM_COMPRESSES)
            .map(|_| core::array::from_fn(|_| BabyBear::rand(rng)))
            .collect_vec();
        compress_test_inputs.iter().enumerate().for_each(|(i, input)| {
            let mut result_array = permuter.permute(*input);
            if incorrect_trace {
                result_array = core::array::from_fn(|_| BabyBear::rand(rng));
            }
            let prev_ts = BabyBear::from_canonical_usize(i);
            let input_ts = BabyBear::from_canonical_usize(i + 1);
            let output_ts = BabyBear::from_canonical_usize(i + 2);

            let dst = BabyBear::from_canonical_usize(i + 1);
            let left = dst + BabyBear::from_canonical_usize(WIDTH / 2);
            let right = left + BabyBear::from_canonical_usize(WIDTH / 2);

            let compress_event = Poseidon2CompressEvent {
                clk: input_ts,
                dst,
                left,
                right,
                input: *input,
                result_array,
                input_records: dummy_memory_access_records(input.to_vec(), prev_ts, input_ts)
                    .try_into()
                    .unwrap(),
                result_records: dummy_memory_access_records(
                    result_array.to_vec(),
                    input_ts,
                    output_ts,
                )
                .try_into()
                .unwrap(),
            };

            input_exec.poseidon2_compress_events.push(compress_event);
        });

        input_exec
    }

    #[test]
    #[should_panic]
    fn poseidon2_wide_prove_babybear_failure() {
        // Generate test input exec record.
        let input_exec = generate_test_execution_record(true);

        poseidon2_wide_prove_babybear_degree::<3>(input_exec.clone());
        poseidon2_wide_prove_babybear_degree::<9>(input_exec);
    }
}
