use crate::air::{AirInteraction, SP1AirBuilder, Word, WordAirBuilder};
use crate::air::{MachineAir, SubAirBuilder};
use crate::operations::IsZeroOperation;
use crate::utils::pad_to_power_of_two;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::runtime::{ExecutionRecord, MemoryRecord};
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::BaseAir;
use p3_air::{Air, AirBuilder};
use p3_field::AbstractField;
use p3_matrix::MatrixRowSlices;
use sp1_derive::AlignedBorrow;

#[derive(PartialEq)]
pub enum MemoryChipKind {
    Init,
    Finalize,
    Program,
}

pub struct MemoryGlobalChip {
    pub kind: MemoryChipKind,
}

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

impl<F: PrimeField> MachineAir<F> for MemoryGlobalChip {
    type Record = ExecutionRecord;

    fn name(&self) -> String {
        match self.kind {
            MemoryChipKind::Finalize => "MemoryFinalize".to_string(),
            MemoryChipKind::Program => "MemoryProgram".to_string(),
            _ => panic!("should not be called with MemoryChipKind::Initialize"),
        }
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let memory_record = match self.kind {
            MemoryChipKind::Finalize => &input.last_memory_record,
            MemoryChipKind::Program => &input.program_memory_record,
            _ => panic!("should not be called with MemoryChipKind::Initialize"),
        };

        let rows = (0..memory_record.len()) // TODO: change this back to par_iter
            .map(|i| {
                MemoryInitCols::generate_trace_row(
                    memory_record[i].0,
                    &memory_record[i].1,
                    memory_record[i].2,
                )
            })
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
            MemoryChipKind::Finalize => !shard.last_memory_record.is_empty(),
            MemoryChipKind::Program => !shard.program_memory_record.is_empty(),
            _ => panic!("should not be called with MemoryChipKind::Initialize"),
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

impl<F: PrimeField> MemoryInitCols<F> {
    fn generate_trace_row(
        addr: u32,
        record: &MemoryRecord,
        multiplicity: u32,
    ) -> [F; NUM_MEMORY_INIT_COLS] {
        let mut row = [F::zero(); NUM_MEMORY_INIT_COLS];
        let cols: &mut MemoryInitCols<F> = row.as_mut_slice().borrow_mut();

        cols.addr = F::from_canonical_u32(addr);
        cols.shard = F::from_canonical_u32(record.shard);
        cols.timestamp = F::from_canonical_u32(record.timestamp);
        cols.value = record.value.into();
        cols.is_real = F::from_canonical_u32(multiplicity);

        row
    }
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

        if self.kind == MemoryChipKind::Init || self.kind == MemoryChipKind::Program {
            let mut values = vec![AB::Expr::zero(), AB::Expr::zero(), local.addr.into()];
            values.extend(local.value.map(Into::into));
            builder.receive(AirInteraction::new(
                values,
                local.is_real.into(),
                crate::lookup::InteractionKind::Memory,
            ));
        } else {
            let mut values = vec![
                local.shard.into(),
                local.timestamp.into(),
                local.addr.into(),
            ];
            values.extend(local.value.map(Into::into));
            builder.send(AirInteraction::new(
                values,
                local.is_real.into(),
                crate::lookup::InteractionKind::Memory,
            ));
        }
    }
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryInitExtendedCols<T> {
    pub mem_cols: MemoryInitCols<T>,
    pub shard_is_zero: IsZeroOperation<T>,
}

pub(crate) const NUM_MEMORY_INIT_EXTENDED_COLS: usize = size_of::<MemoryInitExtendedCols<u8>>();

pub struct MemoryGlobalInitChip {
    memory_global_chip: MemoryGlobalChip,
}

impl MemoryGlobalInitChip {
    pub fn new() -> Self {
        let memory_global_chip = MemoryGlobalChip::new(MemoryChipKind::Init);
        Self { memory_global_chip }
    }
}

impl<F> BaseAir<F> for MemoryGlobalInitChip {
    fn width(&self) -> usize {
        NUM_MEMORY_INIT_EXTENDED_COLS
    }
}

impl<F: PrimeField> MachineAir<F> for MemoryGlobalInitChip {
    type Record = ExecutionRecord;

    fn name(&self) -> String {
        "MemoryInit".to_string()
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
                cols.shard_is_zero
                    .populate(input.first_memory_record[i].1.shard);

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

impl<AB> Air<AB> for MemoryGlobalInitChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &MemoryInitExtendedCols<AB::Var> = main.row_slice(0).borrow();

        let mut sub_builder =
            SubAirBuilder::<AB, MemoryGlobalChip, AB::Var>::new(builder, 0..NUM_MEMORY_INIT_COLS);

        // Eval the plonky3 keccak air
        self.memory_global_chip.eval(&mut sub_builder);

        builder
            .when(local.shard_is_zero.result)
            .assert_word_zero(local.mem_cols.value);
    }
}
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

        let chip: MemoryGlobalChip = MemoryGlobalChip::new(MemoryChipKind::Init);

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

        let chip = MemoryGlobalChip::new(MemoryChipKind::Init);

        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&runtime.record, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }

    #[test]
    fn test_memory_lookup_interactions() {
        setup_logger();
        let program = sha_extend_program();
        let mut runtime = Runtime::new(program);
        runtime.run();

        let machine = RiscvAir::machine(BabyBearPoseidon2::new());
        debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
            machine.chips(),
            &runtime.record,
            vec![InteractionKind::Memory],
        );
    }

    #[test]
    fn test_byte_lookup_interactions() {
        setup_logger();
        let program = sha_extend_program();
        let mut runtime = Runtime::new(program);
        runtime.run();

        let machine = RiscvAir::machine(BabyBearPoseidon2::new());
        debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
            machine.chips(),
            &runtime.record,
            vec![InteractionKind::Byte],
        );
    }
}
