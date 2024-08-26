use crate::memory::{MemoryCols, MemoryReadCols, MemoryWriteCols};

use crate::air::MemoryAirBuilder;
use crate::utils::pad_rows;
use generic_array::{ArrayLength, GenericArray};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field, PackedValue, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{align, Register};
use sp1_core_executor::{events::ByteRecord, syscalls::SyscallCode, ExecutionRecord, Program};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{BaseAirBuilder, MachineAir, SP1AirBuilder};
use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct MemCopyCols<T, NumWords: ArrayLength, NumBytes: ArrayLength> {
    is_real: T,
    shard: T,
    channel: T,
    clk: T,
    nonce: T,
    src_ptr: T,
    dst_ptr: T,
    src_offset: (T, T),
    nbytes: T, // Think it's redundant, since this information is in nbytes_record
    src_offset_record: MemoryReadCols<T>,
    nbytes_record: MemoryReadCols<T>,
    src_aligned: GenericArray<MemoryReadCols<T>, NumWords>,
    dst_reads: GenericArray<MemoryReadCols<T>, NumWords>,
    dst_writes: GenericArray<MemoryWriteCols<T>, NumWords>,
    src_corrected: GenericArray<T, NumBytes>,
    // _marker: PhantomData<(NumWords, NumBytes)>,
}

pub struct MemCopyChip<NumWords: ArrayLength, NumBytes: ArrayLength> {
    _marker: PhantomData<(NumWords, NumBytes)>,
}

const A2_U8: u8 = 12;
const A3_U8: u8 = 13;

impl<NumWords: ArrayLength, NumBytes: ArrayLength> MemCopyChip<NumWords, NumBytes> {
    const NUM_COLS: usize = core::mem::size_of::<MemCopyCols<u8, NumWords, NumBytes>>();

    pub fn new() -> Self {
        println!("MemCopyChip<{}> NUM_COLS = {}", NumBytes::USIZE, Self::NUM_COLS);
        // assert_eq!(NumWords::USIZE * 4, NumBytes::USIZE);
        Self { _marker: PhantomData }
    }

    pub fn syscall_id() -> u32 {
        SyscallCode::MEMCPY_32.syscall_id()
    }
}

impl<F: PrimeField32, NumWords: ArrayLength + Send + Sync, NumBytes: ArrayLength + Send + Sync>
    MachineAir<F> for MemCopyChip<NumWords, NumBytes>
{
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        format!("MemCopy{}Chip", NumWords::USIZE)
    }

    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        let mut rows = vec![];
        let mut new_byte_lookup_events = vec![];
        let events = input.memcpy32_events.clone();

        for event in events {
            let mut row = Vec::with_capacity(Self::NUM_COLS);
            row.resize(Self::NUM_COLS, F::zero());
            let cols: &mut MemCopyCols<F, NumWords, NumBytes> = row.as_mut_slice().borrow_mut();

            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.channel = F::from_canonical_u8(event.channel);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.src_ptr = F::from_canonical_u32(event.src_ptr);
            cols.dst_ptr = F::from_canonical_u32(event.dst_ptr);

            // Source offset is represented as 2 bits
            let src_offset = (event.src_ptr % 4) as u8;
            cols.src_offset.1 = F::from_canonical_u8((src_offset >> 1) & 1);
            cols.src_offset.0 = F::from_canonical_u8(src_offset & 1);
            cols.src_offset_record.populate(
                event.channel,
                event.src_ptr_offset_record,
                &mut new_byte_lookup_events,
            );
            cols.nbytes_record.populate(
                event.channel,
                event.nbytes_record,
                &mut new_byte_lookup_events,
            );
            cols.nbytes = F::from_canonical_u8(event.nbytes);

            /*
                cols.nonce = F::from_canonical_u32(
                    output
                        .nonce_lookup
                        .get(&event.lookup_id)
                        .copied()
                        .expect("should not be none"),
                );
            */

            for i in 0..NumWords::USIZE {
                cols.src_aligned[i].populate(
                    event.channel,
                    event.src_read_records[i],
                    &mut new_byte_lookup_events,
                );
            }

            for i in 0..NumWords::USIZE {}

            let bytes_shifted = cols
                .src_aligned
                .iter()
                .flat_map(|read| read.access.value.into_iter())
                .skip((event.src_ptr % 4) as usize)
                .take(NumBytes::USIZE)
                .collect::<GenericArray<F, NumBytes>>();

            cols.src_corrected = bytes_shifted;

            // for i in 0..NumWords::USIZE {
            //     cols.dst_writes[i].populate(
            //         event.channel,
            //         event.write_records[i],
            //         &mut new_byte_lookup_events,
            //     );
            // }

            rows.push(row);
        }
        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows(&mut rows, || vec![F::zero(); Self::NUM_COLS]);

        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), Self::NUM_COLS);
        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut MemCopyCols<F, NumWords, NumBytes> =
                trace.values[i * Self::NUM_COLS..(i + 1) * Self::NUM_COLS].borrow_mut();
            //cols.nonce = F::from_canonical_usize(i);
        }
        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.memcpy32_events.is_empty()
    }
}

impl<F, NumWords: ArrayLength + Sync, NumBytes: ArrayLength + Sync> BaseAir<F>
    for MemCopyChip<NumWords, NumBytes>
{
    fn width(&self) -> usize {
        Self::NUM_COLS
    }
}

impl<AB: SP1AirBuilder, NumWords: ArrayLength + Sync, NumBytes: ArrayLength + Sync> Air<AB>
    for MemCopyChip<NumWords, NumBytes>
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0);
        let row: &MemCopyCols<AB::Var, NumWords, NumBytes> = (*row).borrow();

        // Validate the read from the source.
        builder.eval_memory_access_slice(
            row.shard,
            row.channel,
            row.clk.into(),
            row.src_ptr,
            &row.src_aligned,
            row.is_real,
        );

        // Validate the write to the destination.
        // builder.eval_memory_access_slice(
        //     row.shard,
        //     row.channel,
        //     row.clk.into(),
        //     row.dst_ptr,
        //     &row.dst_writes,
        //     row.is_real,
        // );

        // Check that nbytes matches the value in the register.
        builder.eval_memory_access(
            row.shard,
            row.channel,
            row.clk.into(),
            AB::Expr::from_canonical_u8(A2_U8),
            &row.nbytes_record,
            row.is_real,
        );

        // Check that src_offset matches the value in the register.
        builder.eval_memory_access(
            row.shard,
            row.channel,
            row.clk.into(),
            AB::Expr::from_canonical_u8(A3_U8),
            &row.src_offset_record,
            row.is_real,
        );

        // builder.assert_bool(row.src_offset.0);
        // builder.assert_bool(row.src_offset.1);

        // let one = AB::Expr::one();
        // let aligned_bytes = row.src_aligned.iter().flat_map(|a| a.access.value.into_iter());

        // let mut src_offset_0 =
        //     builder.when((one.clone() - row.src_offset.1) * (one.clone() - row.src_offset.0));
        // src_offset_0
        //     .assert_all_eq(aligned_bytes.clone().take(NumBytes::USIZE), row.src_corrected.clone());

        // let mut src_offset_1 = builder.when((one.clone() - row.src_offset.1) * (row.src_offset.0));
        // src_offset_1.assert_all_eq(
        //     aligned_bytes.clone().skip(1).take(NumBytes::USIZE),
        //     row.src_corrected.clone(),
        // );

        // let mut src_offset_2 = builder.when((row.src_offset.1) * (one.clone() - row.src_offset.0));
        // src_offset_2.assert_all_eq(
        //     aligned_bytes.clone().skip(2).take(NumBytes::USIZE),
        //     row.src_corrected.clone(),
        // );

        // let mut src_offset_3 = builder.when(row.src_offset.1 * row.src_offset.0);
        // src_offset_3.assert_all_eq(
        //     aligned_bytes.clone().skip(3).take(NumBytes::USIZE),
        //     row.src_corrected.clone(),
        // );

        builder.receive_syscall(
            row.shard,
            row.channel,
            row.clk,
            row.nonce,
            AB::F::from_canonical_u32(Self::syscall_id()),
            row.src_ptr,
            row.dst_ptr,
            row.is_real,
        );
    }
}
