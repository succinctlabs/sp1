use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::{ParallelIterator, ParallelSlice};

use super::{
    columns::{ShaCompressCols, NUM_SHA_COMPRESS_COLS},
    ShaCompressChip, ShaCompressEvent, SHA_COMPRESS_K,
};
use crate::{
    air::{MachineAir, Word},
    bytes::{event::ByteRecord, ByteLookupEvent},
    runtime::{ExecutionRecord, Program},
    utils::pad_rows,
};

impl<F: PrimeField32> MachineAir<F> for ShaCompressChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "ShaCompress".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let rows = Vec::new();

        let mut wrapped_rows = Some(rows);
        for i in 0..input.sha_compress_events.len() {
            let event = input.sha_compress_events[i].clone();
            self.event_to_rows(&event, &mut wrapped_rows, &mut Vec::new());
        }
        let mut rows = wrapped_rows.unwrap();

        let num_real_rows = rows.len();

        pad_rows(&mut rows, || [F::zero(); NUM_SHA_COMPRESS_COLS]);

        // Set the octet_num and octect columns for the padded rows.
        let mut octet_num = 0;
        let mut octet = 0;
        for row in rows[num_real_rows..].iter_mut() {
            let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();
            cols.octet_num[octet_num] = F::one();
            cols.octet[octet] = F::one();

            // If in the compression phase, set the k value.
            if octet_num != 0 && octet_num != 9 {
                let compression_idx = octet_num - 1;
                let k_idx = compression_idx * 8 + octet;
                cols.k = Word::from(SHA_COMPRESS_K[k_idx]);
            }

            octet = (octet + 1) % 8;
            if octet == 0 {
                octet_num = (octet_num + 1) % 10;
            }

            cols.is_last_row = cols.octet[7] * cols.octet_num[9];
        }

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHA_COMPRESS_COLS,
        );

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut ShaCompressCols<F> = trace.values
                [i * NUM_SHA_COMPRESS_COLS..(i + 1) * NUM_SHA_COMPRESS_COLS]
                .borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.sha_compress_events.len() / num_cpus::get(), 1);

        let blu_batches = input
            .sha_compress_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
                events.iter().for_each(|event| {
                    self.event_to_rows::<F>(event, &mut None, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_sharded_byte_lookup_events(blu_batches.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.sha_compress_events.is_empty()
    }
}

impl ShaCompressChip {
    fn event_to_rows<F: PrimeField32>(
        &self,
        event: &ShaCompressEvent,
        rows: &mut Option<Vec<[F; NUM_SHA_COMPRESS_COLS]>>,
        blu: &mut impl ByteRecord,
    ) {
        let shard = event.shard;
        let channel = event.channel;

        let og_h = event.h;

        let mut octet_num_idx = 0;

        // Load a, b, c, d, e, f, g, h.
        for j in 0..8usize {
            let mut row = [F::zero(); NUM_SHA_COMPRESS_COLS];
            let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();

            cols.shard = F::from_canonical_u32(event.shard);
            cols.channel = F::from_canonical_u8(event.channel);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.w_ptr = F::from_canonical_u32(event.w_ptr);
            cols.h_ptr = F::from_canonical_u32(event.h_ptr);

            cols.octet[j] = F::one();
            cols.octet_num[octet_num_idx] = F::one();
            cols.is_initialize = F::one();

            cols.mem
                .populate_read(channel, event.h_read_records[j], blu);
            cols.mem_addr = F::from_canonical_u32(event.h_ptr + (j * 4) as u32);

            cols.a = Word::from(event.h_read_records[0].value);
            cols.b = Word::from(event.h_read_records[1].value);
            cols.c = Word::from(event.h_read_records[2].value);
            cols.d = Word::from(event.h_read_records[3].value);
            cols.e = Word::from(event.h_read_records[4].value);
            cols.f = Word::from(event.h_read_records[5].value);
            cols.g = Word::from(event.h_read_records[6].value);
            cols.h = Word::from(event.h_read_records[7].value);

            cols.is_real = F::one();
            cols.start = cols.is_real * cols.octet_num[0] * cols.octet[0];
            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }

        // Performs the compress operation.
        let mut h_array = event.h;
        for j in 0..64 {
            if j % 8 == 0 {
                octet_num_idx += 1;
            }
            let mut row = [F::zero(); NUM_SHA_COMPRESS_COLS];
            let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();

            cols.k = Word::from(SHA_COMPRESS_K[j]);
            cols.is_compression = F::one();
            cols.octet[j % 8] = F::one();
            cols.octet_num[octet_num_idx] = F::one();

            cols.shard = F::from_canonical_u32(event.shard);
            cols.channel = F::from_canonical_u8(event.channel);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.w_ptr = F::from_canonical_u32(event.w_ptr);
            cols.h_ptr = F::from_canonical_u32(event.h_ptr);
            cols.mem
                .populate_read(channel, event.w_i_read_records[j], blu);
            cols.mem_addr = F::from_canonical_u32(event.w_ptr + (j * 4) as u32);

            let a = h_array[0];
            let b = h_array[1];
            let c = h_array[2];
            let d = h_array[3];
            let e = h_array[4];
            let f = h_array[5];
            let g = h_array[6];
            let h = h_array[7];
            cols.a = Word::from(a);
            cols.b = Word::from(b);
            cols.c = Word::from(c);
            cols.d = Word::from(d);
            cols.e = Word::from(e);
            cols.f = Word::from(f);
            cols.g = Word::from(g);
            cols.h = Word::from(h);

            let e_rr_6 = cols.e_rr_6.populate(blu, shard, channel, e, 6);
            let e_rr_11 = cols.e_rr_11.populate(blu, shard, channel, e, 11);
            let e_rr_25 = cols.e_rr_25.populate(blu, shard, channel, e, 25);
            let s1_intermediate = cols
                .s1_intermediate
                .populate(blu, shard, channel, e_rr_6, e_rr_11);
            let s1 = cols
                .s1
                .populate(blu, shard, channel, s1_intermediate, e_rr_25);

            let e_and_f = cols.e_and_f.populate(blu, shard, channel, e, f);
            let e_not = cols.e_not.populate(blu, shard, channel, e);
            let e_not_and_g = cols.e_not_and_g.populate(blu, shard, channel, e_not, g);
            let ch = cols.ch.populate(blu, shard, channel, e_and_f, e_not_and_g);

            let temp1 = cols.temp1.populate(
                blu,
                shard,
                channel,
                h,
                s1,
                ch,
                event.w[j],
                SHA_COMPRESS_K[j],
            );

            let a_rr_2 = cols.a_rr_2.populate(blu, shard, channel, a, 2);
            let a_rr_13 = cols.a_rr_13.populate(blu, shard, channel, a, 13);
            let a_rr_22 = cols.a_rr_22.populate(blu, shard, channel, a, 22);
            let s0_intermediate = cols
                .s0_intermediate
                .populate(blu, shard, channel, a_rr_2, a_rr_13);
            let s0 = cols
                .s0
                .populate(blu, shard, channel, s0_intermediate, a_rr_22);

            let a_and_b = cols.a_and_b.populate(blu, shard, channel, a, b);
            let a_and_c = cols.a_and_c.populate(blu, shard, channel, a, c);
            let b_and_c = cols.b_and_c.populate(blu, shard, channel, b, c);
            let maj_intermediate = cols
                .maj_intermediate
                .populate(blu, shard, channel, a_and_b, a_and_c);
            let maj = cols
                .maj
                .populate(blu, shard, channel, maj_intermediate, b_and_c);

            let temp2 = cols.temp2.populate(blu, shard, channel, s0, maj);

            let d_add_temp1 = cols.d_add_temp1.populate(blu, shard, channel, d, temp1);
            let temp1_add_temp2 = cols
                .temp1_add_temp2
                .populate(blu, shard, channel, temp1, temp2);

            h_array[7] = g;
            h_array[6] = f;
            h_array[5] = e;
            h_array[4] = d_add_temp1;
            h_array[3] = c;
            h_array[2] = b;
            h_array[1] = a;
            h_array[0] = temp1_add_temp2;

            cols.is_real = F::one();
            cols.start = cols.is_real * cols.octet_num[0] * cols.octet[0];

            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }

        let mut v: [u32; 8] = (0..8)
            .map(|i| h_array[i])
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        octet_num_idx += 1;
        // Store a, b, c, d, e, f, g, h.
        for j in 0..8usize {
            let mut row = [F::zero(); NUM_SHA_COMPRESS_COLS];
            let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();

            cols.shard = F::from_canonical_u32(event.shard);
            cols.channel = F::from_canonical_u8(event.channel);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.w_ptr = F::from_canonical_u32(event.w_ptr);
            cols.h_ptr = F::from_canonical_u32(event.h_ptr);

            cols.octet[j] = F::one();
            cols.octet_num[octet_num_idx] = F::one();
            cols.is_finalize = F::one();

            cols.finalize_add
                .populate(blu, shard, channel, og_h[j], h_array[j]);
            cols.mem
                .populate_write(channel, event.h_write_records[j], blu);
            cols.mem_addr = F::from_canonical_u32(event.h_ptr + (j * 4) as u32);

            v[j] = h_array[j];
            cols.a = Word::from(v[0]);
            cols.b = Word::from(v[1]);
            cols.c = Word::from(v[2]);
            cols.d = Word::from(v[3]);
            cols.e = Word::from(v[4]);
            cols.f = Word::from(v[5]);
            cols.g = Word::from(v[6]);
            cols.h = Word::from(v[7]);

            match j {
                0 => cols.finalized_operand = cols.a,
                1 => cols.finalized_operand = cols.b,
                2 => cols.finalized_operand = cols.c,
                3 => cols.finalized_operand = cols.d,
                4 => cols.finalized_operand = cols.e,
                5 => cols.finalized_operand = cols.f,
                6 => cols.finalized_operand = cols.g,
                7 => cols.finalized_operand = cols.h,
                _ => panic!("unsupported j"),
            };

            cols.is_real = F::one();
            cols.is_last_row = cols.octet[7] * cols.octet_num[9];
            cols.start = cols.is_real * cols.octet_num[0] * cols.octet[0];

            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }
    }
}
