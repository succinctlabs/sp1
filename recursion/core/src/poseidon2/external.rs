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
    }
}
