use crate::air::{AirInteraction, SP1AirBuilder, Word};
use crate::air::{MachineAir, WordAirBuilder};
use crate::utils::pad_to_power_of_two;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::runtime::{ExecutionRecord, Program};
use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};
use p3_air::BaseAir;
use p3_air::{Air, AirBuilder};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use p3_util::indices_arr;
use sp1_derive::AlignedBorrow;

use super::MemoryInitializeFinalizeEvent;

#[derive(PartialEq)]
pub enum MemoryChipKind {
    Initialize,
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

    type Program = Program;

    fn name(&self) -> String {
        match self.kind {
            MemoryChipKind::Initialize => "MemoryInit".to_string(),
            MemoryChipKind::Finalize => "MemoryFinalize".to_string(),
            MemoryChipKind::Program => "MemoryProgram".to_string(),
        }
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let memory_events = match self.kind {
            MemoryChipKind::Initialize => &input.memory_initialize_events,
            MemoryChipKind::Finalize => &input.memory_finalize_events,
            MemoryChipKind::Program => &input.program_memory_events,
        };
        let rows: Vec<[F; 8]> = (0..memory_events.len()) // TODO: change this back to par_iter
            .map(|i| {
                let MemoryInitializeFinalizeEvent {
                    addr,
                    value,
                    shard,
                    timestamp,
                    used,
                } = memory_events[i];
                let mut row = [F::zero(); NUM_MEMORY_INIT_COLS];
                let cols: &mut MemoryInitCols<F> = row.as_mut_slice().borrow_mut();
                cols.addr = F::from_canonical_u32(addr);
                cols.shard = F::from_canonical_u32(shard);
                cols.timestamp = F::from_canonical_u32(timestamp);
                cols.value = value.into();
                cols.is_real = F::from_canonical_u32(used);

                row
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
            MemoryChipKind::Initialize => !shard.memory_initialize_events.is_empty(),
            MemoryChipKind::Finalize => !shard.memory_finalize_events.is_empty(),
            MemoryChipKind::Program => !shard.program_memory_events.is_empty(),
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
        let local = main.row_slice(0);
        let local: &MemoryInitCols<AB::Var> = (*local).borrow();

        // Dummy constraint of degree 3.
        builder.assert_eq(
            local.is_real * local.is_real * local.is_real,
            local.is_real * local.is_real * local.is_real,
        );

        if self.kind == MemoryChipKind::Initialize || self.kind == MemoryChipKind::Program {
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

        // Register %x0 should always be 0. See 2.6 Load and Store Instruction on
        // P.18 of the RISC-V spec.  To ensure that, we expect that the first row of the Initialize
        // and Finalize global memory chip is for register %x0 (i.e. addr = 0x0), and that those rows
        // have a value of 0.  Additionally, in the CPU air, we ensure that whenever op_a is set to
        // %x0, its value is 0.
        if self.kind == MemoryChipKind::Initialize || self.kind == MemoryChipKind::Finalize {
            builder.when_first_row().assert_zero(local.addr);
            builder.when_first_row().assert_word_zero(local.value);
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::lookup::{debug_interactions_with_all_chips, InteractionKind};
    use crate::runtime::tests::simple_program;
    use crate::runtime::Runtime;
    use crate::stark::MachineRecord;
    use crate::stark::{RiscvAir, StarkGenericConfig};
    use crate::syscall::precompiles::sha256::extend_tests::sha_extend_program;
    use crate::utils::{setup_logger, BabyBearPoseidon2};
    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use p3_baby_bear::BabyBear;

    #[test]
    fn test_memory_generate_trace() {
        let program = simple_program();
        let mut runtime = Runtime::new(program);
        runtime.run();
        let shard = runtime.record.clone();

        let chip: MemoryGlobalChip = MemoryGlobalChip::new(MemoryChipKind::Initialize);

        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);

        let chip: MemoryGlobalChip = MemoryGlobalChip::new(MemoryChipKind::Finalize);
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);

        for mem_event in shard.memory_finalize_events {
            println!("{:?}", mem_event);
        }
    }

    #[test]
    fn test_memory_prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let program = simple_program();
        let mut runtime = Runtime::new(program);
        runtime.run();

        let chip = MemoryGlobalChip::new(MemoryChipKind::Initialize);

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
        let program_clone = program.clone();
        let mut runtime = Runtime::new(program);
        runtime.run();
        let machine: crate::stark::MachineStark<BabyBearPoseidon2, RiscvAir<BabyBear>> =
            RiscvAir::machine(BabyBearPoseidon2::new());
        let (pkey, _) = machine.setup(&program_clone);
        let shards = machine.shard(
            runtime.record,
            &<ExecutionRecord as MachineRecord>::Config::default(),
        );
        assert_eq!(shards.len(), 1);
        debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
            &machine,
            &pkey,
            &shards,
            vec![InteractionKind::Memory],
        );
    }

    #[test]
    fn test_byte_lookup_interactions() {
        setup_logger();
        let program = sha_extend_program();
        let program_clone = program.clone();
        let mut runtime = Runtime::new(program);
        runtime.run();
        let machine = RiscvAir::machine(BabyBearPoseidon2::new());
        let (pkey, _) = machine.setup(&program_clone);
        let shards = machine.shard(
            runtime.record,
            &<ExecutionRecord as MachineRecord>::Config::default(),
        );
        assert_eq!(shards.len(), 1);
        debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
            &machine,
            &pkey,
            &shards,
            vec![InteractionKind::Byte],
        );
    }
}
