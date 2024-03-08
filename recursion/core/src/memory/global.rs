use core::mem::size_of;
use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use sp1_core::air::SP1AirBuilder;
use sp1_core::utils::indices_arr;
use sp1_core::{air::MachineAir, utils::pad_to_power_of_two};
use sp1_derive::AlignedBorrow;
use std::borrow::Borrow;
use std::mem::transmute;

use crate::memory::Word;
use crate::runtime::ExecutionRecord;

#[allow(dead_code)]
#[derive(PartialEq)]
pub enum MemoryChipKind {
    Init,
    Finalize,
    Program,
}

pub struct MemoryGlobalChip {
    pub kind: MemoryChipKind,
}

#[allow(dead_code)]
impl MemoryGlobalChip {
    pub fn new(kind: MemoryChipKind) -> Self {
        Self { kind }
    }
}

impl<F> BaseAir<F> for MemoryGlobalChip {
    fn width(&self) -> usize {
        NUM_MEMORY_INIT_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryGlobalChip {
    type Record = ExecutionRecord<F>;

    fn name(&self) -> String {
        match self.kind {
            MemoryChipKind::Init => "MemoryInit".to_string(),
            MemoryChipKind::Finalize => "MemoryFinalize".to_string(),
            MemoryChipKind::Program => "MemoryProgram".to_string(),
        }
    }

    #[allow(unused_variables)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let memory_record = match self.kind {
            MemoryChipKind::Init => &input.first_memory_record,
            MemoryChipKind::Finalize => &input.last_memory_record,
            MemoryChipKind::Program => &input.program_memory_record,
        };
        let rows: Vec<[F; 8]> = (0..memory_record.len()) // TODO: change this back to par_iter
            .map(|i| [F::zero(); NUM_MEMORY_INIT_COLS])
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_INIT_COLS,
        );

        pad_to_power_of_two::<NUM_MEMORY_INIT_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        match self.kind {
            MemoryChipKind::Init => !shard.first_memory_record.is_empty(),
            MemoryChipKind::Finalize => !shard.last_memory_record.is_empty(),
            MemoryChipKind::Program => !shard.program_memory_record.is_empty(),
        }
    }
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryInitCols<T> {
    pub shard: T,
    pub timestamp: T,
    pub addr: T,
    pub value: Word<T>,
    pub is_real: T,
}

pub(crate) const NUM_MEMORY_INIT_COLS: usize = size_of::<MemoryInitCols<u8>>();
#[allow(dead_code)]
pub(crate) const MEMORY_INIT_COL_MAP: MemoryInitCols<usize> = make_col_map();

const fn make_col_map() -> MemoryInitCols<usize> {
    let indices_arr = indices_arr::<NUM_MEMORY_INIT_COLS>();
    unsafe { transmute::<[usize; NUM_MEMORY_INIT_COLS], MemoryInitCols<usize>>(indices_arr) }
}

impl<AB> Air<AB> for MemoryGlobalChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &MemoryInitCols<AB::Var> = main.row_slice(0).borrow();

        // Dummy constraint of degree 3.
        builder.assert_eq(
            local.is_real * local.is_real * local.is_real,
            local.is_real * local.is_real * local.is_real,
        );
    }
}
