#![allow(clippy::needless_range_loop)]

use std::borrow::Borrow;
use std::borrow::BorrowMut;
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
use self::columns::Poseidon2Mut;

/// The width of the permutation.
pub const WIDTH: usize = 16;
pub const RATE: usize = WIDTH / 2;

pub const NUM_EXTERNAL_ROUNDS: usize = 8;
pub const NUM_INTERNAL_ROUNDS: usize = 13;
pub const NUM_ROUNDS: usize = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS;

/// A chip that implements addition for the opcode Poseidon2Wide.
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
        row: &'b mut Vec<F>,
    ) -> Box<dyn Poseidon2Mut<'a, F> + 'a> {
        if DEGREE == 3 {
            let convert: &mut Poseidon2Degree3<F> = row.as_mut_slice().borrow_mut();
            Box::new(convert)
        } else if DEGREE == 9 || DEGREE == 17 {
            let convert: &mut Poseidon2Degree9<F> = row.as_mut_slice().borrow_mut();
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
pub(crate) mod tests {
    use std::array;
    use std::mem::size_of;
    use std::time::Instant;

    use crate::machine::RecursionAir;
    use crate::poseidon2_wide::columns::memory::{
        POSEIDON2_MEMORY_PREPROCESSED_WIDTH, POSEIDON2_MEMORY_WIDTH,
    };
    use crate::poseidon2_wide::columns::permutation::{PermutationNoSbox, PermutationSBox};
    use crate::poseidon2_wide::events::Poseidon2Event;
    use crate::{ExecutionRecord, RecursionProgram};
    use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
    use p3_matrix::dense::RowMajorMatrix;
    use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
    use p3_symmetric::Permutation;
    use rand::random;
    use sp1_core::air::MachineAir;
    use sp1_core::stark::StarkGenericConfig;
    use sp1_core::utils::{
        inner_perm, run_test_machine, uni_stark_prove, uni_stark_verify, BabyBearPoseidon2,
    };

    use zkhash::ark_ff::UniformRand;

    use super::{Poseidon2WideChip, WIDTH};

    fn poseidon2_wide_prove_babybear_degree<const DEGREE: usize>(
        input_exec: ExecutionRecord<BabyBear>,
    ) {
        println!("Num Memory Columns: {}", POSEIDON2_MEMORY_WIDTH);
        println!(
            "Num preprocess columns: {}",
            POSEIDON2_MEMORY_PREPROCESSED_WIDTH
        );
        println!(
            "Num Permutation Cols for Degree 3: {}",
            size_of::<PermutationSBox<u8>>()
        );
        println!(
            "Num Permutation Cols for Degree 9: {}",
            size_of::<PermutationNoSbox<u8>>()
        );
        let mut program = RecursionProgram::default();
        program.num_poseidon2_events = input_exec.poseidon2_events.len();

        let machine = RecursionAir::<_, DEGREE>::machine(BabyBearPoseidon2::default());
        let (pk, vk) = machine.setup(&program);

        let record = input_exec;

        let result = run_test_machine(record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }

    pub(crate) fn generate_test_execution_record(
        incorrect_trace: bool,
    ) -> ExecutionRecord<BabyBear> {
        const NUM_ABSORBS: usize = 1000;
        // const NUM_COMPRESSES: usize = 1000;

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
        hash_test_input_sizes.iter().for_each(|_| {
            let hash_state = [BabyBear::rand(rng); WIDTH];
            let mut perm_output = permuter.permute(hash_state);
            if incorrect_trace {
                perm_output = [BabyBear::rand(rng); WIDTH];
            }

            input_exec
                .poseidon2_events
                .push(Poseidon2Event::dummy_from_input(hash_state, perm_output));
        });
        input_exec
    }

    #[test]
    fn poseidon2_wide_prove_babybear_success() {
        // Generate test input exec record.
        let input_exec = generate_test_execution_record(false);

        poseidon2_wide_prove_babybear_degree::<3>(input_exec.clone());
        poseidon2_wide_prove_babybear_degree::<9>(input_exec);
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
