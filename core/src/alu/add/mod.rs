use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;

use crate::air::{CurtaAirBuilder, Word};
use valida_derive::AlignedBorrow;

use crate::operations::AddOperation;
use crate::runtime::{Opcode, Segment};
use crate::utils::{pad_to_power_of_two, Chip};

pub const NUM_ADD_COLS: usize = size_of::<AddCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default)]
#[repr(C)]
pub struct AddCols<T> {
    /// Instance of `AddOperation` to handle addition logic in `AddChip`'s ALU operations.
    pub add_operation: AddOperation<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Selector to know whether this row is enabled.
    pub is_real: T,
}

/// A chip that implements addition for the opcodes ADD and ADDI.
pub struct AddChip;

impl AddChip {
    pub fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField> Chip<F> for AddChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let mut rows: Vec<[F; NUM_ADD_COLS]> = vec![];
        let add_events = segment.add_events.clone();
        for event in add_events.iter() {
            let mut row = [F::zero(); NUM_ADD_COLS];
            let cols: &mut AddCols<F> = unsafe { transmute(&mut row) };

            cols.add_operation.populate(segment, event.b, event.c);
            cols.b = Word::from(event.b);
            cols.c = Word::from(event.c);
            cols.is_real = F::one();
            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_ADD_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_ADD_COLS, F>(&mut trace.values);

        trace
    }

    fn name(&self) -> String {
        "Add".to_string()
    }
}

impl<F> BaseAir<F> for AddChip {
    fn width(&self) -> usize {
        NUM_ADD_COLS
    }
}

impl<AB> Air<AB> for AddChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &AddCols<AB::Var> = main.row_slice(0).borrow();

        AddOperation::<AB::F>::eval(
            builder,
            local.b,
            local.c,
            local.add_operation,
            local.is_real,
        );

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        #[allow(clippy::eq_op)]
        builder.assert_zero(
            local.b[0] * local.b[0] * local.c[0] - local.b[0] * local.b[0] * local.c[0],
        );

        // Receive the arguments.
        builder.receive_alu(
            AB::F::from_canonical_u32(Opcode::ADD as u32),
            local.add_operation.value,
            local.b,
            local.c,
            local.is_real,
        );
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use p3_matrix::dense::RowMajorMatrix;

    use p3_uni_stark::{prove, verify};
    use rand::{thread_rng, Rng};

    use crate::{
        alu::AluEvent,
        runtime::{Opcode, Segment},
        utils::{BabyBearPoseidon2, Chip, StarkUtils},
    };

    use super::AddChip;

    #[test]
    fn generate_trace() {
        let mut segment = Segment::default();
        segment.add_events = vec![AluEvent::new(0, Opcode::ADD, 14, 8, 6)];
        let chip = AddChip::new();
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
            let result = operand_1.wrapping_add(operand_2);

            segment
                .add_events
                .push(AluEvent::new(0, Opcode::ADD, result, operand_1, operand_2));
        }

        let chip = AddChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
