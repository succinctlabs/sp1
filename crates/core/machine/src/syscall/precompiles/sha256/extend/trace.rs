use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{ParallelIterator, ParallelSlice};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, PrecompileEvent, ShaExtendEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_stark::air::MachineAir;
use std::borrow::BorrowMut;

use super::{ShaExtendChip, ShaExtendCols, NUM_SHA_EXTEND_COLS};

impl<F: PrimeField32> MachineAir<F> for ShaExtendChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "ShaExtend".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let rows = Vec::new();

        let mut new_byte_lookup_events = Vec::new();
        let mut wrapped_rows = Some(rows);
        for (_, event) in input.get_precompile_events(SyscallCode::SHA_EXTEND).iter() {
            let event =
                if let PrecompileEvent::ShaExtend(event) = event { event } else { unreachable!() };
            self.event_to_rows(event, &mut wrapped_rows, &mut new_byte_lookup_events);
        }

        let mut rows = wrapped_rows.unwrap();
        let nb_rows = rows.len();
        let mut padded_nb_rows = nb_rows.next_power_of_two();
        if padded_nb_rows == 2 || padded_nb_rows == 1 {
            padded_nb_rows = 4;
        }
        for i in nb_rows..padded_nb_rows {
            let mut row = [F::zero(); NUM_SHA_EXTEND_COLS];
            let cols: &mut ShaExtendCols<F> = row.as_mut_slice().borrow_mut();
            cols.populate_flags(i);
            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHA_EXTEND_COLS,
        );

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut ShaExtendCols<F> =
                trace.values[i * NUM_SHA_EXTEND_COLS..(i + 1) * NUM_SHA_EXTEND_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = input.get_precompile_events(SyscallCode::SHA_EXTEND);
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
                events.iter().for_each(|(_, event)| {
                    let event = if let PrecompileEvent::ShaExtend(event) = event {
                        event
                    } else {
                        unreachable!()
                    };
                    self.event_to_rows::<F>(event, &mut None, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_sharded_byte_lookup_events(blu_batches.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::SHA_EXTEND).is_empty()
        }
    }
}

impl ShaExtendChip {
    fn event_to_rows<F: PrimeField32>(
        &self,
        event: &ShaExtendEvent,
        rows: &mut Option<Vec<[F; NUM_SHA_EXTEND_COLS]>>,
        blu: &mut impl ByteRecord,
    ) {
        let shard = event.shard;
        for j in 0..48usize {
            let mut row = [F::zero(); NUM_SHA_EXTEND_COLS];
            let cols: &mut ShaExtendCols<F> = row.as_mut_slice().borrow_mut();
            cols.is_real = F::one();
            cols.populate_flags(j);
            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.w_ptr = F::from_canonical_u32(event.w_ptr);

            cols.w_i_minus_15.populate(event.w_i_minus_15_reads[j], blu);
            cols.w_i_minus_2.populate(event.w_i_minus_2_reads[j], blu);
            cols.w_i_minus_16.populate(event.w_i_minus_16_reads[j], blu);
            cols.w_i_minus_7.populate(event.w_i_minus_7_reads[j], blu);

            // `s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift
            // 3)`.
            let w_i_minus_15 = event.w_i_minus_15_reads[j].value;
            let w_i_minus_15_rr_7 = cols.w_i_minus_15_rr_7.populate(blu, shard, w_i_minus_15, 7);
            let w_i_minus_15_rr_18 = cols.w_i_minus_15_rr_18.populate(blu, shard, w_i_minus_15, 18);
            let w_i_minus_15_rs_3 = cols.w_i_minus_15_rs_3.populate(blu, shard, w_i_minus_15, 3);
            let s0_intermediate =
                cols.s0_intermediate.populate(blu, shard, w_i_minus_15_rr_7, w_i_minus_15_rr_18);
            let s0 = cols.s0.populate(blu, shard, s0_intermediate, w_i_minus_15_rs_3);

            // `s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift
            // 10)`.
            let w_i_minus_2 = event.w_i_minus_2_reads[j].value;
            let w_i_minus_2_rr_17 = cols.w_i_minus_2_rr_17.populate(blu, shard, w_i_minus_2, 17);
            let w_i_minus_2_rr_19 = cols.w_i_minus_2_rr_19.populate(blu, shard, w_i_minus_2, 19);
            let w_i_minus_2_rs_10 = cols.w_i_minus_2_rs_10.populate(blu, shard, w_i_minus_2, 10);
            let s1_intermediate =
                cols.s1_intermediate.populate(blu, shard, w_i_minus_2_rr_17, w_i_minus_2_rr_19);
            let s1 = cols.s1.populate(blu, shard, s1_intermediate, w_i_minus_2_rs_10);

            // Compute `s2`.
            let w_i_minus_7 = event.w_i_minus_7_reads[j].value;
            let w_i_minus_16 = event.w_i_minus_16_reads[j].value;
            cols.s2.populate(blu, shard, w_i_minus_16, s0, w_i_minus_7, s1);

            cols.w_i.populate(event.w_i_writes[j], blu);

            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }
    }
}
