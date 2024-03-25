use p3_air::{Air, BaseAir};
use p3_field::PrimeField;
use p3_matrix::{dense::RowMajorMatrix, MatrixRowSlices};
use sp1_derive::AlignedBorrow;

use crate::{
    air::{MachineAir, SP1AirBuilder, SubAirBuilder, WordAirBuilder},
    operations::IsZeroOperation,
    runtime::ExecutionRecord,
    utils::pad_to_power_of_two,
};

use super::{MemoryChipKind, MemoryGlobalChip, MemoryInitCols, NUM_MEMORY_INIT_COLS};

use core::mem::size_of;
use std::borrow::{Borrow, BorrowMut};

/// Chip for the Initial global memory.
///
/// This chip is for the Initial global memory. It contains a MemoryGlobalChip subchip.  The main
/// additional contraint that the MemoryGlobalInitialChip has is that it asserts the initial X0
/// values is zero.
pub struct MemoryGlobalInitialChip {
    memory_global_chip: MemoryGlobalChip,
}

impl MemoryGlobalInitialChip {
    pub fn new() -> Self {
        let memory_global_chip = MemoryGlobalChip::new(MemoryChipKind::Initial);
        Self { memory_global_chip }
    }
}

impl<F> BaseAir<F> for MemoryGlobalInitialChip {
    fn width(&self) -> usize {
        NUM_MEMORY_INIT_EXTENDED_COLS
    }
}

impl<F: PrimeField> MachineAir<F> for MemoryGlobalInitialChip {
    type Record = ExecutionRecord;

    fn name(&self) -> String {
        "MemoryInitialize".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let rows = (0..input.first_memory_record.len()) // TODO: change this back to par_iter
            .map(|i| {
                let mut row = [F::zero(); NUM_MEMORY_INIT_EXTENDED_COLS];
                let mem_record = MemoryInitCols::generate_trace_row(
                    input.first_memory_record[i].0,
                    &input.first_memory_record[i].1,
                    input.first_memory_record[i].2,
                );
                row[0..NUM_MEMORY_INIT_COLS].copy_from_slice(&mem_record);

                let cols: &mut MemoryInitExtendedCols<F> = row.as_mut_slice().borrow_mut();
                cols.addr_is_zero.populate(input.first_memory_record[i].0);

                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_INIT_EXTENDED_COLS,
        );

        pad_to_power_of_two::<NUM_MEMORY_INIT_EXTENDED_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.first_memory_record.is_empty()
    }
}

impl<AB> Air<AB> for MemoryGlobalInitialChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &MemoryInitExtendedCols<AB::Var> = main.row_slice(0).borrow();

        // Create a sub builder to eval the MemoryGlobalChip constraints.
        let mut sub_builder =
            SubAirBuilder::<AB, MemoryGlobalChip, AB::Var>::new(builder, 0..NUM_MEMORY_INIT_COLS);

        // Eval the MemoryGlobalChip constraints.
        self.memory_global_chip.eval(&mut sub_builder);

        // Verify that the initial X0 (which is memory with addr == 0) value is 0.
        builder
            .when(local.addr_is_zero.result)
            .assert_word_zero(local.mem_cols.value);
    }
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryInitExtendedCols<T> {
    pub mem_cols: MemoryInitCols<T>,
    pub addr_is_zero: IsZeroOperation<T>,
}

pub(crate) const NUM_MEMORY_INIT_EXTENDED_COLS: usize = size_of::<MemoryInitExtendedCols<u8>>();

#[cfg(test)]
mod tests {

    use crate::lookup::{debug_interactions_with_all_chips, InteractionKind};
    use crate::memory::MemoryGlobalChip;
    use crate::runtime::Runtime;
    use crate::stark::{RiscvAir, StarkGenericConfig};
    use crate::syscall::precompiles::sha256::extend_tests::sha_extend_program;
    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::runtime::tests::simple_program;
    use crate::utils::{setup_logger, BabyBearPoseidon2};

    #[test]
    fn test_memory_generate_trace() {
        let program = simple_program();
        let mut runtime = Runtime::new(program);
        runtime.run();
        let shard = runtime.record.clone();

        let chip = MemoryGlobalInitialChip::new();

        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);

        let chip: MemoryGlobalChip = MemoryGlobalChip::new(MemoryChipKind::Finalize);
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);

        for (addr, record, _) in shard.last_memory_record {
            println!("{:?} {:?}", addr, record);
        }
    }

    #[test]
    fn test_memory_prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let program = simple_program();
        let mut runtime = Runtime::new(program);
        runtime.run();

        let chip = MemoryGlobalInitialChip::new();

        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&runtime.record, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
