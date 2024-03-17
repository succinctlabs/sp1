use core::borrow::Borrow;
use core::mem::size_of;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
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
    pub sbox_input_deg3: [T; STATE_SIZE],
    pub sbox_input_deg5: [T; STATE_SIZE],
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
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Poseidon2Cols<AB::Var> = main.row_slice(0).borrow();

        let add_rc = local
            .input
            .iter()
            .map(|x| *x + AB::F::one())
            .collect::<Vec<_>>();
        let sbox_input_deg3 = local
            .sbox_input_deg3
            .iter()
            .map(|x| *x * *x * *x)
            .collect::<Vec<_>>();
        for i in 0..STATE_SIZE {
            builder.assert_eq(sbox_input_deg3[i], local.sbox_input_deg3[i]);
        }
        let sbox_input_deg5 = local
            .sbox_input_deg5
            .iter()
            .enumerate()
            .map(|(i, x)| sbox_input_deg3[i] * *x * *x)
            .collect::<Vec<_>>();
        for i in 0..STATE_SIZE {
            builder.assert_eq(sbox_input_deg5[i], local.sbox_input_deg5[i]);
        }

        // // Degree 3 constraint to avoid "OodEvaluationMismatch".
        // builder.assert_zero(
        //     local.b[0] * local.b[0] * local.c[0] - local.b[0] * local.b[0] * local.c[0],
        // );
    }
}
