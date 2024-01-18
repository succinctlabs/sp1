use std::mem::transmute;

use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    bytes::{ByteLookupEvent, ByteOpcode},
    disassembler::WORD_SIZE,
    runtime::Segment,
    utils::{pad_to_power_of_two, Chip},
};

use super::{
    air::{FieldCols, NUM_FIELD_COLS},
    FieldChip,
};

impl<F: PrimeField> Chip<F> for FieldChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let mut byte_ltu_lookup_events = Vec::new();

        let rows = segment
            .field_events
            .iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_FIELD_COLS];
                let cols: &mut FieldCols<F> = unsafe { transmute(&mut row) };
                let b = event.b.to_le_bytes();
                let c = event.c.to_le_bytes();

                let mut differing_byte = [F::zero(); WORD_SIZE];
                let mut byte_lookup_event_added = false;
                for i in (0..WORD_SIZE).rev() {
                    if b[i] != c[i] {
                        differing_byte[i] = F::one();
                        byte_ltu_lookup_events.push(ByteLookupEvent::new(
                            ByteOpcode::LTU,
                            (b[i] < c[i]) as u8,
                            0,
                            b[i],
                            c[i],
                        ));
                        cols.b_byte = F::from_canonical_u8(b[i]);
                        cols.c_byte = F::from_canonical_u8(c[i]);
                        byte_lookup_event_added = true;
                        break;
                    }
                }

                // This means that b and c are equal.
                if !byte_lookup_event_added {
                    assert!(event.b == event.c);
                    byte_ltu_lookup_events.push(ByteLookupEvent::new(
                        ByteOpcode::LTU,
                        false as u8,
                        0,
                        0,
                        0,
                    ));
                    cols.b_byte = F::zero();
                    cols.c_byte = F::zero();
                }

                cols.lt = F::from_bool(event.ltu);
                cols.b = F::from_canonical_u32(event.b);
                cols.b_word = event.b.into();
                cols.c = F::from_canonical_u32(event.c);
                cols.c_word = event.c.into();

                cols.is_real = F::one();
                row
            })
            .collect::<Vec<_>>();

        if !byte_ltu_lookup_events.is_empty() {
            segment.add_byte_lookup_events(byte_ltu_lookup_events);
        }

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_FIELD_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_FIELD_COLS, F>(&mut trace.values);

        trace
    }
}
