use crate::cpu::MemoryRecordEnum;
use crate::runtime::ExecutionRecord;
use crate::syscall::precompiles::blake2b::compress::columns::NUM_BLAKE2B_COMPRESS_INNER_COLS;
use crate::syscall::precompiles::blake2b::{Blake2bCompressInnerChip, NUM_MIX_ROUNDS};
use crate::utils::pad_rows;
use p3_maybe_rayon::prelude::{ParallelIterator, ParallelSlice};
use std::borrow::BorrowMut;

use crate::air::MachineAir;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use tracing::instrument;

use super::columns::Blake2bCompressInnerCols;
use super::{
    MIX_INDEX, MIX_INPUT_SIZE, MSG_ELE_PER_CALL, NUM_MSG_WORDS_PER_CALL, OPERATION_COUNT,
    SIGMA_PERMUTATIONS, STATE_NUM_WORDS, STATE_SIZE,
};

impl<F: PrimeField> MachineAir<F> for Blake2bCompressInnerChip {
    fn name(&self) -> String {
        "Blake2bInnerCompress".to_string()
    }

    #[instrument(name = "generate blake2b inner compression trace", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // compute the number of events to process in each chunk.
        let chunk_size = std::cmp::max(
            input.blake2b_compress_inner_events.len() / num_cpus::get(),
            1,
        );

        // Generate the trace rows & corresponding records for each chunk of events concurrently.
        let rows_and_records = input
            .blake2b_compress_inner_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut records = ExecutionRecord::default();
                let mut new_field_events = Vec::new();

                let rows = events
                    .iter()
                    .flat_map(|event| {
                        let mut rows = Vec::new();

                        let mut clk = event.clk;
                        for round in 0..NUM_MIX_ROUNDS {
                            for operation in 0..OPERATION_COUNT {
                                let mut row = [F::zero(); NUM_BLAKE2B_COMPRESS_INNER_COLS];
                                let cols: &mut Blake2bCompressInnerCols<F> =
                                    row.as_mut_slice().borrow_mut();

                                // populating the basic values to the columns.
                                {
                                    cols.segment = F::from_canonical_u32(event.shard);
                                    cols.clk = F::from_canonical_u32(clk);

                                    cols.mix_round = F::from_canonical_u32(round as u32);
                                    cols.is_mix_round_index_n[round] = F::one();

                                    cols.operation_index = F::from_canonical_u32(operation as u32);
                                    cols.is_operation_index_n[operation] = F::one();

                                    for i in 0..STATE_SIZE {
                                        cols.state_index[i] =
                                            F::from_canonical_usize(MIX_INDEX[operation][i]);
                                    }

                                    for i in 0..MSG_ELE_PER_CALL {
                                        cols.message_index[i] = F::from_canonical_usize(
                                            SIGMA_PERMUTATIONS[round][2 * operation + i],
                                        );
                                    }
                                }

                                // populating memory values.
                                {
                                    cols.message_ptr = F::from_canonical_u32(event.message_ptr);
                                    for i in 0..NUM_MSG_WORDS_PER_CALL {
                                        cols.message_reads[i].populate(
                                            event.message_reads[round][operation][i],
                                            &mut new_field_events,
                                        )
                                    }

                                    cols.state_ptr = F::from_canonical_u32(event.state_ptr);
                                    for i in 0..STATE_NUM_WORDS {
                                        cols.state_reads_writes[i].populate(
                                            MemoryRecordEnum::Write(
                                                event.state_writes[round][operation][i],
                                            ),
                                            &mut new_field_events,
                                        )
                                    }
                                }

                                // apply the mix operation.
                                {
                                    // populating the input to the mix function.
                                    let input: [u64; MIX_INPUT_SIZE] = [
                                        ((event.state_writes[round][operation][1].prev_value
                                            as u64)
                                            << 32)
                                            | event.state_writes[round][operation][0].prev_value
                                                as u64,
                                        ((event.state_writes[round][operation][3].prev_value
                                            as u64)
                                            << 32)
                                            | event.state_writes[round][operation][2].prev_value
                                                as u64,
                                        ((event.state_writes[round][operation][5].prev_value
                                            as u64)
                                            << 32)
                                            | event.state_writes[round][operation][4].prev_value
                                                as u64,
                                        ((event.state_writes[round][operation][7].prev_value
                                            as u64)
                                            << 32)
                                            | event.state_writes[round][operation][6].prev_value
                                                as u64,
                                        ((event.message_reads[round][operation][1].value as u64)
                                            << 32)
                                            | event.message_reads[round][operation][0].value as u64,
                                        ((event.message_reads[round][operation][3].value as u64)
                                            << 32)
                                            | event.message_reads[round][operation][2].value as u64,
                                    ];

                                    cols.mix.populate(&mut records, input);
                                }

                                clk += 4;

                                cols.is_real = F::one();

                                rows.push(row);
                            }
                        }

                        rows
                    })
                    .collect::<Vec<_>>();
                records.add_field_events(&new_field_events);
                (rows, records)
            })
            .collect::<Vec<_>>();

        let mut rows = Vec::new();
        for mut row_and_record in rows_and_records {
            rows.extend(row_and_record.0);
            output.append(&mut row_and_record.1);
        }

        pad_rows(&mut rows, || [F::zero(); NUM_BLAKE2B_COMPRESS_INNER_COLS]);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BLAKE2B_COMPRESS_INNER_COLS,
        )
    }
}
