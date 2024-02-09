use std::borrow::BorrowMut;

use crate::precompiles::blake3::{Blake3CompressInnerChip, ROUND_COUNT};
use crate::{
    precompiles::blake3::compress::columns::NUM_BLAKE3_COMPRESS_INNER_COLS,
    utils::NB_ROWS_PER_SHARD,
};

use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::{runtime::Segment, utils::Chip};

use super::columns::Blake3CompressInnerCols;
use super::{
    g_func, G_INDEX, G_INPUT_SIZE, G_OUTPUT_SIZE, MSG_SCHEDULE, NUM_MSG_WORDS_PER_CALL,
    NUM_STATE_WORDS_PER_CALL, OPERATION_COUNT,
};

impl<F: PrimeField> Chip<F> for Blake3CompressInnerChip {
    fn name(&self) -> String {
        "Blake3CompressInner".to_string()
    }

    fn shard(&self, input: &Segment, outputs: &mut Vec<Segment>) {
        let shards = input
            .blake3_compress_inner_events
            .chunks(NB_ROWS_PER_SHARD)
            .collect::<Vec<_>>();
        for i in 0..shards.len() {
            outputs[i].blake3_compress_inner_events = shards[i].to_vec();
        }
    }

    // TODO: The vast majority of this logic can be shared with the second external round.
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let mut new_field_events = Vec::new();

        for i in 0..segment.blake3_compress_inner_events.len() {
            let event = segment.blake3_compress_inner_events[i];

            let mut clk = event.clk;
            for round in 0..ROUND_COUNT {
                for operation in 0..OPERATION_COUNT {
                    let mut row = [F::zero(); NUM_BLAKE3_COMPRESS_INNER_COLS];
                    let cols: &mut Blake3CompressInnerCols<F> = row.as_mut_slice().borrow_mut();

                    // Assign basic values to the columns.
                    {
                        cols.segment = F::from_canonical_u32(event.segment);
                        cols.clk = F::from_canonical_u32(clk);

                        cols.round_index = F::from_canonical_u32(round as u32);
                        cols.is_round_index_n[round] = F::one();

                        cols.operation_index = F::from_canonical_u32(operation as u32);
                        cols.is_operation_index_n[operation] = F::one();

                        for i in 0..NUM_STATE_WORDS_PER_CALL {
                            cols.state_index[i] = F::from_canonical_usize(G_INDEX[operation][i]);
                        }

                        for i in 0..NUM_MSG_WORDS_PER_CALL {
                            cols.msg_schedule[i] =
                                F::from_canonical_usize(MSG_SCHEDULE[round][2 * operation + i]);
                        }
                    }
                    // Memory reads & writes.
                    {
                        cols.state_ptr = F::from_canonical_u32(event.state_ptr);
                        for i in 0..G_INPUT_SIZE {
                            cols.mem_reads[i]
                                .populate(event.reads[round][operation][i], &mut new_field_events);
                            clk += 4;
                        }
                    }
                    let input: [u32; G_INPUT_SIZE] = event.reads[round][operation]
                        .iter()
                        .map(|read| read.value)
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap();

                    let result = cols.g.populate(segment, input);

                    // Memory writes.
                    {
                        for i in 0..G_OUTPUT_SIZE {
                            cols.mem_writes[i]
                                .populate(event.writes[round][operation][i], &mut new_field_events);
                            clk += 4;
                            assert_eq!(
                                result[i], event.writes[round][operation][i].value,
                                "round: {:?}, operation: {:?}, i: {:?}",
                                round, operation, i
                            )
                        }
                    }
                    // if (round == 0 && operation == 0) || (round == 1 && operation == 2) {
                    //     println!("cols.round = {:#?}", cols.round_index);
                    //     println!("cols.operation = {:#?}", cols.operation_index);
                    //     println!("cols.clk = {:#?}", cols.clk);
                    //     println!("cols.mem_reads = {:?}", cols.mem_reads);
                    //     println!("cols.mem_writes = {:?}", cols.mem_writes);
                    // }

                    cols.is_real = F::one();

                    rows.push(row);
                }
            }
        }

        segment.field_events.extend(new_field_events);

        let nb_rows = rows.len();
        let mut padded_nb_rows = nb_rows.next_power_of_two();
        if padded_nb_rows == 2 || padded_nb_rows == 1 {
            padded_nb_rows = 4;
        }

        for _ in nb_rows..padded_nb_rows {
            let mut row = [F::zero(); NUM_BLAKE3_COMPRESS_INNER_COLS];
            let cols: &mut Blake3CompressInnerCols<F> = row.as_mut_slice().borrow_mut();
            // Put this value in this padded row to avoid failing the constraint.
            cols.round_index = F::from_canonical_usize(ROUND_COUNT);

            rows.push(row);
        }
        for mut row in rows.clone() {
            let cols: &mut Blake3CompressInnerCols<F> = row.as_mut_slice().borrow_mut();
            println!(
                "is_operation_index_n[OPERATION_COUNT - 1] = {}, round_index = {}",
                cols.is_operation_index_n[OPERATION_COUNT - 1],
                cols.round_index
            );
        }

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BLAKE3_COMPRESS_INNER_COLS,
        )
    }
}
