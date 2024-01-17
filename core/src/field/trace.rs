use std::mem::transmute;

use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::{air::Word, disassembler::WORD_SIZE, runtime::Segment, utils::Chip};

use super::{
    air::{FieldCols, NUM_FIELD_COLS},
    FieldChip,
};

impl<F: PrimeField> Chip<F> for FieldChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = segment
            .field_lt_events
            .par_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_FIELD_COLS];
                let cols: &mut FieldCols<F> = unsafe { transmute(&mut row) };
                let b = event.b.to_le_bytes();
                let c = event.c.to_le_bytes();
                let lt = event.b < event.c;

                let mut differing_byte = [F::zero(); WORD_SIZE];
                for i in (0..WORD_SIZE).rev() {
                    if b[i] != c[i] {
                        differing_byte[i] = F::one();
                        break;
                    }
                }

                cols.lt = F::from_bool(lt);
                cols.b = F::from_canonical_u32(event.b);
                cols.b_word = Word(b.map(F::from_canonical_u8));
                cols.c = F::from_canonical_u32(event.c);
                cols.c_word = Word(c.map(F::from_canonical_u8));

                cols.is_real = F::one();
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_FIELD_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_ADD_COLS, F>(&mut trace.values);

        trace
    }
}
