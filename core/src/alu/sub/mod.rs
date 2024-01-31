use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use p3_maybe_rayon::prelude::*;

use valida_derive::AlignedBorrow;

use crate::air::{CurtaAirBuilder, Word};
use crate::runtime::{Opcode, Segment};
use crate::utils::{pad_to_power_of_two, Chip};

/// The number of main trace columns for `SubChip`.
pub const NUM_SUB_COLS: usize = size_of::<SubCols<u8>>();

/// A chip that implements subtraction for the opcode SUB.
#[derive(Default)]
pub struct SubChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
pub struct SubCols<T> {
    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Trace.
    pub carry: [T; 3],

    /// Selector to know whether this row is enabled.
    pub is_real: T,
}

impl<F: PrimeField> Chip<F> for SubChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = segment
            .sub_events
            .par_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_SUB_COLS];
                let cols: &mut SubCols<F> = row.as_mut_slice().borrow_mut();
                let a = event.a.to_le_bytes();
                let b = event.b.to_le_bytes();
                let c = event.c.to_le_bytes();

                let mut carry = [0u8, 0u8, 0u8];
                if b[0] < c[0] {
                    carry[0] = 1;
                    cols.carry[0] = F::one();
                }

                if (b[1] as u16) < c[1] as u16 + carry[0] as u16 {
                    carry[1] = 1;
                    cols.carry[1] = F::one();
                }

                if (b[2] as u16) < c[2] as u16 + carry[1] as u16 {
                    carry[2] = 1;
                    cols.carry[2] = F::one();
                }

                cols.a = Word(a.map(F::from_canonical_u8));
                cols.b = Word(b.map(F::from_canonical_u8));
                cols.c = Word(c.map(F::from_canonical_u8));
                cols.is_real = F::one();
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

    fn name(&self) -> String {
        "Sub".to_string()
    }
}

impl<F> BaseAir<F> for SubChip {
    fn width(&self) -> usize {
        NUM_SUB_COLS
    }
}

impl<AB> Air<AB> for SubChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &SubCols<AB::Var> = main.row_slice(0).borrow();

        let one = AB::F::one();
        let base = AB::F::from_canonical_u32(1 << 8);

        // For each limb, assert that difference between the carried result and the non-carried
        // result is either zero or minus the base.
        // Note that the overflow variables can be have a value of -256 (mod P), so the field
        // should be big enough to handle that.
        let overflow_0 = local.b[0] - local.c[0] - local.a[0];
        let overflow_1 = local.b[1] - local.c[1] - local.a[1] - local.carry[0];
        let overflow_2 = local.b[2] - local.c[2] - local.a[2] - local.carry[1];
        let overflow_3 = local.b[3] - local.c[3] - local.a[3] - local.carry[2];
        builder.assert_zero(overflow_0.clone() * (overflow_0.clone() + base));
        builder.assert_zero(overflow_1.clone() * (overflow_1.clone() + base));
        builder.assert_zero(overflow_2.clone() * (overflow_2.clone() + base));
        builder.assert_zero(overflow_3.clone() * (overflow_3.clone() + base));

        // If the carry is one, then the overflow must be the base.
        builder.assert_zero(local.carry[0] * (overflow_0.clone() + base));
        builder.assert_zero(local.carry[1] * (overflow_1.clone() + base));
        builder.assert_zero(local.carry[2] * (overflow_2.clone() + base));

        // If the carry is not one, then the overflow must be zero.
        builder.assert_zero((local.carry[0] - one) * overflow_0.clone());
        builder.assert_zero((local.carry[1] - one) * overflow_1.clone());
        builder.assert_zero((local.carry[2] - one) * overflow_2.clone());

        // Assert that the carry is either zero or one.
        builder.assert_bool(local.carry[0]);
        builder.assert_bool(local.carry[1]);
        builder.assert_bool(local.carry[2]);

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(
            local.a[0] * local.b[0] * local.c[0] - local.a[0] * local.b[0] * local.c[0],
        );

        // Receive the arguments.
        builder.receive_alu(
            AB::F::from_canonical_u32(Opcode::SUB as u32),
            local.a,
            local.b,
            local.c,
            local.is_real,
        )
    }
}

#[cfg(test)]
mod tests {

    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{thread_rng, Rng};

    use super::SubChip;
    use crate::{
        alu::AluEvent,
        runtime::{Opcode, Segment},
        utils::{BabyBearPoseidon2, Chip, StarkUtils},
    };

    #[test]
    fn generate_trace() {
        let mut segment = Segment::default();
        segment.sub_events = vec![AluEvent::new(0, Opcode::SUB, 14, 8, 6)];
        let chip = SubChip {};
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new(&mut thread_rng());
        let mut challenger = config.challenger();

        let mut segment = Segment::default();

        for _i in 0..1000 {
            let operand_1 = thread_rng().gen_range(0..u32::MAX);
            let operand_2 = thread_rng().gen_range(0..u32::MAX);
            let result = operand_1.wrapping_sub(operand_2);

            segment
                .sub_events
                .push(AluEvent::new(0, Opcode::SUB, result, operand_1, operand_2));
        }
        let chip = SubChip::default();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
