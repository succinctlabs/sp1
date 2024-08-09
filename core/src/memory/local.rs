use std::{borrow::BorrowMut, mem::size_of};

use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use sp1_derive::AlignedBorrow;

use crate::{
    air::{MachineAir, Word},
    runtime::{ExecutionRecord, Program},
    utils::pad_to_power_of_two,
};

use super::MemoryChipType;

pub(crate) const NUM_MEMORY_LOCAL_INIT_COLS: usize = size_of::<MemoryLocalInitCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryLocalInitCols<T> {
    /// The shard number of the memory access.
    pub shard: T,

    /// The timestamp of the memory access.
    pub timestamp: T,

    /// The address of the memory access.
    pub addr: T,

    pub value: Word<T>,

    /// Whether the memory access is a real access.
    pub is_real: T,
}

pub struct MemoryLocalChip {
    pub kind: MemoryChipType,
}

impl MemoryLocalChip {
    /// Creates a new memory chip with a certain type.
    pub const fn new(kind: MemoryChipType) -> Self {
        Self { kind }
    }
}

impl<F> BaseAir<F> for MemoryLocalChip {
    fn width(&self) -> usize {
        NUM_MEMORY_LOCAL_INIT_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryLocalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        match self.kind {
            MemoryChipType::Initialize => "MemoryLocalInit".to_string(),
            MemoryChipType::Finalize => "MemoryLocalFinalize".to_string(),
        }
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let local_memory_accesses = match self.kind {
            MemoryChipType::Initialize => &input.local_memory_initialize_access,
            MemoryChipType::Finalize => &input.local_memory_finalize_access,
        };

        let mut rows =
            Vec::<[F; NUM_MEMORY_LOCAL_INIT_COLS]>::with_capacity(local_memory_accesses.len());
        for (addr, mem_access) in local_memory_accesses.iter() {
            let mut row = [F::zero(); NUM_MEMORY_LOCAL_INIT_COLS];
            let cols: &mut MemoryLocalInitCols<F> = row.as_mut_slice().borrow_mut();

            cols.shard = F::from_canonical_u32(mem_access.shard);
            cols.timestamp = F::from_canonical_u32(mem_access.timestamp);
            cols.addr = F::from_canonical_u32(*addr);
            cols.value = mem_access.value.into();
            cols.is_real = F::one();

            rows.push(row);
        }
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_LOCAL_INIT_COLS,
        );

        pad_to_power_of_two::<NUM_MEMORY_LOCAL_INIT_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        match self.kind {
            MemoryChipType::Initialize => !shard.local_memory_initialize_access.is_empty(),
            MemoryChipType::Finalize => !shard.local_memory_finalize_access.is_empty(),
        }
    }
}
