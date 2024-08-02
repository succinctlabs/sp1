use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use serde::{Deserialize, Serialize};
use sp1_derive::AlignedBorrow;

use crate::{
    air::{MachineAir, PublicValues, Word, SP1_PROOF_NUM_PV_ELTS},
    runtime::{ExecutionRecord, MemoryRecordEnum, Program},
    stark::SP1AirBuilder,
    utils::pad_rows_fixed,
};

use super::{MemoryAccessCols, MemoryReadWriteCols};

pub(crate) const NUM_MEMORY_LOCAL_COLS: usize = size_of::<MemoryLocalCols<u8>>();

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct MemoryLocalEvent {
    pub addr: u32,
    pub mem_record: MemoryRecordEnum,
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryLocalCols<T> {
    pub channel: T,

    /// The address of the memory access.
    pub addr: T,

    /// Value of the memory access.
    pub value: Word<T>,

    pub prev_value: Word<T>,

    /// The clk of the memory access.
    pub clk: T,

    /// The previous clk and shard of the memory access.
    pub prev_shard: T,
    pub prev_clk: T,

    pub diff_16bit_limb: T,

    /// This column is the most signficant 8 bit limb of current access timestamp - prev access timestamp.
    pub diff_8bit_limb: T,

    pub compare_clk: T,

    pub is_real: T,
}

#[derive(Default)]
/// A memory chip that can initialize or finalize values in memory.
pub struct MemoryLocalChip {}

impl<F> BaseAir<F> for MemoryLocalChip {
    fn width(&self) -> usize {
        NUM_MEMORY_LOCAL_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryLocalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "MemoryLocal".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows: Vec<[F; NUM_MEMORY_LOCAL_COLS]> = Vec::new();

        input.memory_records.iter().for_each(|mem_record| {
            let mut row = [F::zero(); NUM_MEMORY_LOCAL_COLS];
            let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();

            cols.addr = F::from_canonical_u32(mem_record.addr);

            let (value, prev_value, shard, clk, prev_shard, prev_clk) = match mem_record.mem_record
            {
                MemoryRecordEnum::Read(read_record) => (
                    read_record.value,
                    read_record.value,
                    read_record.shard,
                    read_record.timestamp,
                    read_record.prev_shard,
                    read_record.prev_timestamp,
                ),
                MemoryRecordEnum::Write(write_record) => (
                    write_record.value,
                    write_record.prev_value,
                    write_record.shard,
                    write_record.timestamp,
                    write_record.prev_shard,
                    write_record.prev_timestamp,
                ),
            };

            cols.value = value.into();
            cols.prev_value = prev_value.into();
            cols.clk = F::from_canonical_u32(clk);
            cols.prev_shard = F::from_canonical_u32(prev_shard);
            cols.prev_clk = F::from_canonical_u32(prev_clk);
            cols.compare_clk = F::from_bool(shard == prev_shard);

            let diff_minus_one = clk - prev_clk - 1;
            let diff_16bit_limb = (diff_minus_one & 0xffff) as u16;
            cols.diff_16bit_limb = F::from_canonical_u16(diff_16bit_limb);
            let diff_8bit_limb = (diff_minus_one >> 16) & 0xff;
            cols.diff_8bit_limb = F::from_canonical_u32(diff_8bit_limb);

            rows.push(row);
        });

        pad_rows_fixed(&mut rows, || [F::zero(); NUM_MEMORY_LOCAL_COLS], None);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_MEMORY_LOCAL_COLS)
    }

    fn included(&self, record: &Self::Record) -> bool {
        !record.memory_records.is_empty()
    }
}

impl<AB> Air<AB> for MemoryLocalChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryLocalCols<AB::Var> = (*local).borrow();

        let public_values_slice: [AB::Expr; SP1_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| builder.public_values()[i].into());
        let public_values: &PublicValues<Word<AB::Expr>, AB::Expr> =
            public_values_slice.as_slice().borrow();

        builder.receive_memory_access(
            local.channel,
            local.addr,
            local.value,
            local.clk,
            local.is_real,
        );

        builder.eval_memory_access(
            public_values.shard.clone(),
            local.channel,
            local.clk,
            local.addr,
            &MemoryReadWriteCols {
                prev_value: local.prev_value,
                access: MemoryAccessCols {
                    value: local.value,
                    prev_clk: local.prev_clk,
                    prev_shard: local.prev_shard,
                    diff_16bit_limb: local.diff_16bit_limb,
                    diff_8bit_limb: local.diff_8bit_limb,
                    compare_clk: local.compare_clk,
                },
            },
            local.is_real,
        )
    }
}
