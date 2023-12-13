use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::mem::transmute;
use valida_derive::AlignedBorrow;

use crate::air::Word;
use crate::lookup::Interaction;

use super::{pad_to_power_of_two, u32_to_u8_limbs, AluEvent, Chip};

pub const NUM_SUB_COLS: usize = size_of::<SubCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default)]
pub struct SubCols<T> {
    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Trace.
    pub carry: [T; 3],
}

/// A chip that implements subtraction for the opcode SUB.
pub struct SubChip {
    events: Vec<AluEvent>,
}

impl<F: PrimeField> Chip<F> for SubChip {
    fn generate_trace(&self, _: &mut crate::Runtime) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = self
            .events
            .par_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_SUB_COLS];
                let cols: &mut SubCols<F> = unsafe { transmute(&mut row) };
                let a = u32_to_u8_limbs(event.a);
                let b = u32_to_u8_limbs(event.b);
                let c = u32_to_u8_limbs(event.c);

                let mut carry = [0u8, 0u8, 0u8];
                if (b[0] as i32) - (c[0] as i32) < 0 {
                    carry[0] = 1;
                    cols.carry[0] = F::one();
                }
                if (b[1] as u32) - (c[1] as u32) + (carry[0] as u32) > 255 {
                    carry[1] = 1;
                    cols.carry[1] = F::one();
                }
                if (b[2] as u32) - (c[2] as u32) + (carry[1] as u32) > 255 {
                    carry[2] = 1;
                    cols.carry[2] = F::one();
                }

                cols.a = Word(a.map(F::from_canonical_u8));
                cols.b = Word(b.map(F::from_canonical_u8));
                cols.c = Word(c.map(F::from_canonical_u8));
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_SUB_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_SUB_COLS, F>(&mut trace.values);

        trace
    }

    fn sends(&self) -> Vec<Interaction<F>> {
        vec![]
    }

    fn receives(&self) -> Vec<Interaction<F>> {
        vec![]
    }
}

impl<F> BaseAir<F> for SubChip {
    fn width(&self) -> usize {
        NUM_SUB_COLS
    }
}

impl<F, AB> Air<AB> for SubChip
where
    F: PrimeField,
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &SubCols<AB::Var> = main.row_slice(0).borrow();

        let one = AB::F::one();
        let base = AB::F::from_canonical_u32(1 << 8);

        // For each limb, assert that difference between the carried result and the non-carried
        // result is either zero or the base.
        let overflow_0 = local.b[0] - local.c[0] + local.a[0];
        let overflow_1 = local.b[1] - local.c[1] + local.a[1] + local.carry[0];
        let overflow_2 = local.b[2] - local.c[2] + local.a[2] + local.carry[1];
        let overflow_3 = local.b[3] - local.c[3] + local.a[3] + local.carry[2];
        builder.assert_zero(overflow_0.clone() * (overflow_0.clone() - base));
        builder.assert_zero(overflow_1.clone() * (overflow_1.clone() - base));
        builder.assert_zero(overflow_2.clone() * (overflow_2.clone() - base));
        builder.assert_zero(overflow_3.clone() * (overflow_3.clone() - base));

        // If the carry is one, then the overflow must be the base.
        builder.assert_zero(local.carry[0] * (overflow_0.clone() - base.clone()));
        builder.assert_zero(local.carry[1] * (overflow_1.clone() - base.clone()));
        builder.assert_zero(local.carry[2] * (overflow_2.clone() - base.clone()));

        // If the carry is not one, then the overflow must be zero.
        builder.assert_zero((local.carry[0] - one) * overflow_0.clone());
        builder.assert_zero((local.carry[1] - one) * overflow_1.clone());
        builder.assert_zero((local.carry[2] - one) * overflow_2.clone());

        // Assert that the carry is either zero or one.
        builder.assert_bool(local.carry[0]);
        builder.assert_bool(local.carry[1]);
        builder.assert_bool(local.carry[2]);
    }
}
