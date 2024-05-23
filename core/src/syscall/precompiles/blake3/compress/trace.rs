use std::borrow::BorrowMut;

use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;

use super::columns::Blake3CompressInnerCols;
use super::{
    G_INDEX, G_INPUT_SIZE, MSG_SCHEDULE, NUM_MSG_WORDS_PER_CALL, NUM_STATE_WORDS_PER_CALL,
    OPERATION_COUNT,
};
use crate::air::MachineAir;
use crate::bytes::event::ByteRecord;
use crate::runtime::ExecutionRecord;
use crate::runtime::MemoryRecordEnum;
use crate::runtime::Program;
use crate::syscall::precompiles::blake3::compress::columns::NUM_BLAKE3_COMPRESS_INNER_COLS;
use crate::syscall::precompiles::blake3::{Blake3CompressInnerChip, ROUND_COUNT};
use crate::utils::pad_rows;

impl<F: PrimeField32> MachineAir<F> for Blake3CompressInnerChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Blake3CompressInner".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let mut new_byte_lookup_events = Vec::new();

        for i in 0..input.blake3_compress_inner_events.len() {
            let event = input.blake3_compress_inner_events[i].clone();
            let shard = event.shard;
            let channel = event.channel;
            let mut clk = event.clk;
            for round in 0..ROUND_COUNT {
                for operation in 0..OPERATION_COUNT {
                    let mut row = [F::zero(); NUM_BLAKE3_COMPRESS_INNER_COLS];
                    let cols: &mut Blake3CompressInnerCols<F> = row.as_mut_slice().borrow_mut();

                    // Assign basic values to the columns.
                    {
                        cols.shard = F::from_canonical_u32(event.shard);
                        cols.channel = F::from_canonical_u32(event.channel);
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

                        if round == 0 && operation == 0 {
                            cols.ecall_receive = F::one();
                        }
                    }

                    // Memory columns.
                    {
                        cols.message_ptr = F::from_canonical_u32(event.message_ptr);
                        for i in 0..NUM_MSG_WORDS_PER_CALL {
                            cols.message_reads[i].populate(
                                channel,
                                event.message_reads[round][operation][i],
                                &mut new_byte_lookup_events,
                            );
                        }

                        cols.state_ptr = F::from_canonical_u32(event.state_ptr);
                        for i in 0..NUM_STATE_WORDS_PER_CALL {
                            cols.state_reads_writes[i].populate(
                                channel,
                                MemoryRecordEnum::Write(event.state_writes[round][operation][i]),
                                &mut new_byte_lookup_events,
                            );
                        }
                    }

                    // Apply the `g` operation.
                    {
                        let input: [u32; G_INPUT_SIZE] = [
                            event.state_writes[round][operation][0].prev_value,
                            event.state_writes[round][operation][1].prev_value,
                            event.state_writes[round][operation][2].prev_value,
                            event.state_writes[round][operation][3].prev_value,
                            event.message_reads[round][operation][0].value,
                            event.message_reads[round][operation][1].value,
                        ];

                        cols.g.populate(output, shard, channel, input);
                    }

                    clk += 1;

                    cols.is_real = F::one();

                    rows.push(row);
                }
            }
        }

        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows(&mut rows, || [F::zero(); NUM_BLAKE3_COMPRESS_INNER_COLS]);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BLAKE3_COMPRESS_INNER_COLS,
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.blake3_compress_inner_events.is_empty()
    }
}
