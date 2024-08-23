use crate::memory::{MemoryReadCols, MemoryWriteCols};

use crate::air::MemoryAirBuilder;
use crate::utils::{limbs_from_access, limbs_from_prev_access, pad_rows};
use generic_array::{ArrayLength, GenericArray};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{events::ByteRecord, syscalls::SyscallCode, ExecutionRecord, Program};
use sp1_curves::params::Limbs;
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{MachineAir, SP1AirBuilder};
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
    src_access: GenericArray<MemoryReadCols<T>, NumWords>,
    dst_access: GenericArray<MemoryWriteCols<T>, NumWords>,
    nbytes: GenericArray<T, NumBytes>,
}

pub struct MemCopyChip<NumWords: ArrayLength, NumBytes: ArrayLength> {
    _marker: PhantomData<(NumWords, NumBytes)>,
}

impl<NumWords: ArrayLength, NumBytes: ArrayLength> MemCopyChip<NumWords, NumBytes> {
    const NUM_COLS: usize = core::mem::size_of::<MemCopyCols<u8, NumWords, NumBytes>>();

    pub fn new() -> Self {
        println!("MemCopyChip<{}> NUM_COLS = {}", NumBytes::USIZE, Self::NUM_COLS);
        assert_eq!(NumWords::USIZE * 4, NumBytes::USIZE);
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

            for i in 0..NumBytes::USIZE {
                if event.nbytes == i as u8 {
                    cols.nbytes[i] = F::one();
                } else {
                    cols.nbytes[i] = F::zero();
                }
            }

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
                cols.src_access[i].populate(
                    event.channel,
                    event.read_records[i],
                    &mut new_byte_lookup_events,
                );
            }
            for i in 0..NumWords::USIZE {
                cols.dst_access[i].populate(
                    event.channel,
                    event.write_records[i],
                    &mut new_byte_lookup_events,
                );
            }

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

        // let src: Limbs<<AB as AirBuilder>::Var, NumBytes> = limbs_from_prev_access(&row.src_access);
        // let dst: Limbs<<AB as AirBuilder>::Var, NumBytes> = limbs_from_access(&row.dst_access);

        // First, assert that nbytes is less than 32.
        // Do this by checking that each element in nbytes is binary, then that their sum is
        // also binary (all 0 is allowed, in the case of nbytes being 0).
        // for i in 0..NumBytes::USIZE {
        //     builder.assert_bool(row.nbytes[i]);
        // }

        // let mut sum = row.nbytes[0].into();
        // for i in 1..NumBytes::USIZE {
        //     sum = sum + row.nbytes[i];
        // }

        // builder.assert_bool(sum);

        // TODO constrain the memory accesses ...

        // TODO assert eq

        builder.eval_memory_access_slice(
            row.shard,
            row.channel,
            row.clk.into(),
            row.src_ptr,
            &row.src_access,
            row.is_real,
        );
        builder.eval_memory_access_slice(
            row.shard,
            row.channel,
            row.clk.into(),
            row.dst_ptr,
            &row.dst_access,
            row.is_real,
        );

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
