use std::{borrow::BorrowMut, mem::size_of};

use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use sp1_derive::AlignedBorrow;

use crate::{
    air::{MachineAir, Word},
    runtime::{ExecutionRecord, Program},
    stark::SP1AirBuilder,
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
            MemoryChipType::Initialize => {
                println!(
                    "Local memory initialize table: {:?}",
                    input.local_memory_initialize_access.len()
                );
                &input.local_memory_initialize_access
            }
            MemoryChipType::Finalize => {
                println!(
                    "Local memory finalize table: {:?}",
                    input.local_memory_finalize_access.len()
                );
                &input.local_memory_finalize_access
            }
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

impl<AB> Air<AB> for MemoryLocalChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {}
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::lookup::{debug_interactions_with_all_chips, InteractionKind};
    use crate::runtime::tests::simple_program;
    use crate::runtime::Runtime;
    use crate::stark::RiscvAir;
    use crate::syscall::precompiles::sha256::extend_tests::sha_extend_program;
    use crate::utils::{setup_logger, BabyBearPoseidon2, SP1CoreOpts};
    use p3_baby_bear::BabyBear;

    #[test]
    fn test_local_memory_generate_trace() {
        let program = simple_program();
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        let shard = runtime.records[0].clone();

        let chip: MemoryLocalChip = MemoryLocalChip::new(MemoryChipType::Initialize);

        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);

        let chip: MemoryLocalChip = MemoryLocalChip::new(MemoryChipType::Finalize);
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);

        for mem_event in shard.global_memory_finalize_events {
            println!("{:?}", mem_event);
        }
    }

    // #[test]
    // fn test_memory_lookup_interactions() {
    //     setup_logger();
    //     let program = sha_extend_program();
    //     let program_clone = program.clone();
    //     let mut runtime = Runtime::new(program, SP1CoreOpts::default());
    //     runtime.run().unwrap();
    //     let machine: crate::stark::StarkMachine<BabyBearPoseidon2, RiscvAir<BabyBear>> =
    //         RiscvAir::machine(BabyBearPoseidon2::new());
    //     let (pkey, _) = machine.setup(&program_clone);
    //     let opts = SP1CoreOpts::default();
    //     machine.generate_dependencies(&mut runtime.records, &opts);

    //     let shards = runtime.records;
    //     assert_eq!(shards.len(), 2);
    //     debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
    //         &machine,
    //         &pkey,
    //         &shards,
    //         vec![InteractionKind::Memory],
    //     );
    // }

    // #[test]
    // fn test_byte_lookup_interactions() {
    //     setup_logger();
    //     let program = sha_extend_program();
    //     let program_clone = program.clone();
    //     let mut runtime = Runtime::new(program, SP1CoreOpts::default());
    //     runtime.run().unwrap();
    //     let machine = RiscvAir::machine(BabyBearPoseidon2::new());
    //     let (pkey, _) = machine.setup(&program_clone);
    //     let opts = SP1CoreOpts::default();
    //     machine.generate_dependencies(&mut runtime.records, &opts);

    //     let shards = runtime.records;
    //     assert_eq!(shards.len(), 2);
    //     debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
    //         &machine,
    //         &pkey,
    //         &shards,
    //         vec![InteractionKind::Byte],
    //     );
    // }
}
