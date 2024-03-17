use core::borrow::Borrow;
use core::mem::size_of;
use p3_air::{Air, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use p3_poseidon2::DiffusionMatrixBabybear;
use p3_symmetric::Permutation;
use sp1_core::air::{MachineAir, SP1AirBuilder};
use sp1_core::utils::pad_to_power_of_two;
use sp1_derive::AlignedBorrow;
use tracing::instrument;

use crate::runtime::ExecutionRecord;

/// The number of main trace columns for `AddChip`.
pub const NUM_POSEIDON_2_EXTERNAL_COLS: usize = size_of::<Poseidon2Cols<u8>>();

pub const STATE_SIZE: usize = 8;

/// A chip that implements addition for the opcode ADD.
#[derive(Default)]
pub struct Poseidon2ExternalChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Cols<T> {
    pub input: [T; STATE_SIZE],
    pub sbox_deg3: [T; STATE_SIZE],
    pub sbox_deg5: [T; STATE_SIZE],
    pub output: [T; STATE_SIZE],
    pub is_real: T,
}

impl<F: PrimeField32> MachineAir<F> for Poseidon2ExternalChip {
    type Record = ExecutionRecord<F>;

    fn name(&self) -> String {
        "Poseidon2External".to_string()
    }

    #[instrument(name = "generate add trace", level = "debug", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(vec![], NUM_POSEIDON_2_EXTERNAL_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_POSEIDON_2_EXTERNAL_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        true
    }
}

impl<F> BaseAir<F> for Poseidon2ExternalChip {
    fn width(&self) -> usize {
        NUM_POSEIDON_2_EXTERNAL_COLS
    }
}

impl<AB> Air<AB> for Poseidon2ExternalChip
where
    AB: SP1AirBuilder,
{
    #[allow(clippy::needless_range_loop)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Poseidon2Cols<AB::Var> = main.row_slice(0).borrow();

        // The round constants.
        let rc = [
            AB::F::from_canonical_u32(1),
            AB::F::from_canonical_u32(2),
            AB::F::from_canonical_u32(3),
            AB::F::from_canonical_u32(4),
            AB::F::from_canonical_u32(5),
            AB::F::from_canonical_u32(6),
            AB::F::from_canonical_u32(7),
            AB::F::from_canonical_u32(8),
        ];

        let add_rc = local
            .input
            .iter()
            .zip(rc.iter())
            .map(|(x, rc)| *x + *rc)
            .collect::<Vec<_>>();
        let sbox_deg3 = add_rc
            .iter()
            .map(|x| x.clone() * x.clone() * x.clone())
            .collect::<Vec<_>>();
        for i in 0..STATE_SIZE {
            builder.assert_eq(sbox_deg3[i].clone(), local.sbox_deg3[i]);
        }
        let sbox_deg5 = sbox_deg3
            .iter()
            .zip(add_rc.iter())
            .map(|(x, y)| x.clone() * y.clone() * y.clone())
            .collect::<Vec<_>>();
        for i in 0..STATE_SIZE {
            builder.assert_eq(sbox_deg5[i].clone(), local.sbox_deg5[i]);
        }

        let mut permutation_input_expr: [AB::Expr; 12] = local
            .sbox_deg5
            .iter()
            .map(|x| *x + AB::Expr::zero())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let matrix: [<<AB as p3_air::AirBuilder>::Expr as p3_field::AbstractField>::F; 12] =
            MATRIX_DIAG_16_BABYBEAR_U32
                .iter()
                .map(|x| <<AB as p3_air::AirBuilder>::Expr as p3_field::AbstractField>::F::from_canonical_u32(*x))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
        matmul_internal(&mut permutation_input_expr, matrix);
    }
}

pub fn matmul_internal<F: Field, AF: AbstractField<F = F>, const WIDTH: usize>(
    state: &mut [AF; WIDTH],
    mat_internal_diag_m_1: [F; WIDTH],
) {
    let sum: AF = state.iter().cloned().sum();
    for i in 0..WIDTH {
        state[i] *= AF::from_f(mat_internal_diag_m_1[i]);
        state[i] += sum.clone();
    }
}

const MATRIX_DIAG_16_BABYBEAR_U32: [u32; 16] = [
    0x0a632d94, 0x6db657b7, 0x56fbdc9e, 0x052b3d8a, 0x33745201, 0x5c03108c, 0x0beba37b, 0x258c2e8b,
    0x12029f39, 0x694909ce, 0x6d231724, 0x21c3b222, 0x3c0904a5, 0x01d6acda, 0x27705c83, 0x5231c802,
];
