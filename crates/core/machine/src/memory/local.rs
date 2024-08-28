use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use crate::utils::pad_to_power_of_two;
use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_derive::AlignedBorrow;
use sp1_stark::{
    air::{AirInteraction, InteractionScope, MachineAir, SP1AirBuilder},
    InteractionKind, Word,
};

use super::MemoryChipType;

pub(crate) const NUM_MEMORY_LOCAL_INIT_COLS: usize = size_of::<MemoryLocalInitCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryLocalInitCols<T> {
    /// The shard number of the memory access.
    pub shard: T,

    /// The clk of the memory access.
    pub clk: T,

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
        let mut rows =
            Vec::<[F; NUM_MEMORY_LOCAL_INIT_COLS]>::with_capacity(input.local_memory_access.len());

        let keccak_local_mem_events =
            input.keccak_permute_events.iter().flat_map(|x| x.local_mem_access.iter());

        let ed_add_local_mem_events =
            input.ed_add_events.iter().flat_map(|x| x.local_mem_access.iter());

        let ed_decompress_local_mem_events =
            input.ed_decompress_events.iter().flat_map(|x| x.local_mem_access.iter());

        let sha_compress_local_mem_events =
            input.sha_compress_events.iter().flat_map(|x| x.local_mem_access.iter());

        let sha_extend_local_mem_events =
            input.sha_extend_events.iter().flat_map(|x| x.local_mem_access.iter());

        for local_mem_event in input
            .local_memory_access
            .iter()
            .chain(keccak_local_mem_events)
            .chain(ed_add_local_mem_events)
            .chain(ed_decompress_local_mem_events)
            .chain(sha_compress_local_mem_events)
            .chain(sha_extend_local_mem_events)
        {
            let mut row = [F::zero(); NUM_MEMORY_LOCAL_INIT_COLS];
            let cols: &mut MemoryLocalInitCols<F> = row.as_mut_slice().borrow_mut();

            let mem_access = match self.kind {
                MemoryChipType::Initialize => local_mem_event.initial_mem_access,
                MemoryChipType::Finalize => local_mem_event.final_mem_access,
            };

            cols.shard = F::from_canonical_u32(mem_access.shard);
            cols.clk = F::from_canonical_u32(mem_access.timestamp);
            cols.addr = F::from_canonical_u32(local_mem_event.addr);
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
        let keccak_local_mem_events = shard
            .keccak_permute_events
            .iter()
            .flat_map(|x| x.local_mem_access.iter())
            .collect_vec();

        let ed_add_local_mem_events =
            shard.ed_add_events.iter().flat_map(|x| x.local_mem_access.iter()).collect_vec();

        let ed_decompress_local_mem_events =
            shard.ed_decompress_events.iter().flat_map(|x| x.local_mem_access.iter()).collect_vec();

        let sha_compress_local_mem_events =
            shard.sha_compress_events.iter().flat_map(|x| x.local_mem_access.iter()).collect_vec();

        let sha_extend_local_mem_events =
            shard.sha_extend_events.iter().flat_map(|x| x.local_mem_access.iter()).collect_vec();

        let bn254_fp_local_mem_events =
            shard.bn254_fp_events.iter().flat_map(|x| x.local_mem_access.iter()).collect_vec();

        let bn254_fp2_addsub_local_mem_events = shard
            .bn254_fp2_addsub_events
            .iter()
            .flat_map(|x| x.local_mem_access.iter())
            .collect_vec();

        let bn254_fp2_mul_local_mem_events =
            shard.bn254_fp2_mul_events.iter().flat_map(|x| x.local_mem_access.iter()).collect_vec();

        let bls12381_fp_local_mem_events =
            shard.bls12381_fp_events.iter().flat_map(|x| x.local_mem_access.iter()).collect_vec();

        let bls12381_fp2_addsub_local_mem_events = shard
            .bls12381_fp2_addsub_events
            .iter()
            .flat_map(|x| x.local_mem_access.iter())
            .collect_vec();

        let bls12381_fp2_mul_local_mem_events = shard
            .bls12381_fp2_mul_events
            .iter()
            .flat_map(|x| x.local_mem_access.iter())
            .collect_vec();

        !keccak_local_mem_events.is_empty()
            || !shard.local_memory_access.is_empty()
            || !ed_add_local_mem_events.is_empty()
            || !ed_decompress_local_mem_events.is_empty()
            || !sha_compress_local_mem_events.is_empty()
            || !sha_extend_local_mem_events.is_empty()
            || !bn254_fp_local_mem_events.is_empty()
            || !bn254_fp2_addsub_local_mem_events.is_empty()
            || !bn254_fp2_mul_local_mem_events.is_empty()
            || !bls12381_fp_local_mem_events.is_empty()
            || !bls12381_fp2_addsub_local_mem_events.is_empty()
            || !bls12381_fp2_mul_local_mem_events.is_empty()
    }

    fn included_phase1(&self) -> bool {
        true
    }
}

impl<AB> Air<AB> for MemoryLocalChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryLocalInitCols<AB::Var> = (*local).borrow();

        builder.assert_eq(
            local.is_real * local.is_real * local.is_real,
            local.is_real * local.is_real * local.is_real,
        );

        if self.kind == MemoryChipType::Initialize {
            let mut values = vec![local.shard.into(), local.clk.into(), local.addr.into()];
            values.extend(local.value.map(Into::into));
            builder.send(
                AirInteraction::new(values.clone(), local.is_real.into(), InteractionKind::Memory),
                InteractionScope::Global,
            );
            builder.receive(
                AirInteraction::new(values, local.is_real.into(), InteractionKind::Memory),
                InteractionScope::Local,
            );
        } else {
            let mut values = vec![local.shard.into(), local.clk.into(), local.addr.into()];
            values.extend(local.value.map(Into::into));
            builder.receive(
                AirInteraction::new(values.clone(), local.is_real.into(), InteractionKind::Memory),
                InteractionScope::Global,
            );
            builder.send(
                AirInteraction::new(values, local.is_real.into(), InteractionKind::Memory),
                InteractionScope::Local,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use sp1_core_executor::{programs::tests::simple_program, ExecutionRecord, Executor};
    use sp1_stark::{
        air::{InteractionScope, MachineAir},
        baby_bear_poseidon2::BabyBearPoseidon2,
        debug_interactions_with_all_chips, InteractionKind, SP1CoreOpts, StarkMachine,
    };

    use crate::{
        memory::{MemoryChipType, MemoryLocalChip},
        riscv::RiscvAir,
        syscall::precompiles::sha256::extend_tests::sha_extend_program,
        utils::setup_logger,
    };

    #[test]
    fn test_local_memory_generate_trace() {
        let program = simple_program();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
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

    #[test]
    fn test_memory_lookup_interactions() {
        setup_logger();
        let program = sha_extend_program();
        let program_clone = program.clone();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        let machine: StarkMachine<BabyBearPoseidon2, RiscvAir<BabyBear>> =
            RiscvAir::machine(BabyBearPoseidon2::new());
        let (pkey, _) = machine.setup(&program_clone);
        let opts = SP1CoreOpts::default();
        machine.generate_dependencies(&mut runtime.records, &opts);

        let shards = runtime.records;
        assert_eq!(shards.len(), 2);
        for shard in shards.clone() {
            debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
                &machine,
                &pkey,
                &[shard],
                vec![InteractionKind::Memory],
                InteractionScope::Local,
            );
        }
        debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
            &machine,
            &pkey,
            &shards,
            vec![InteractionKind::Memory],
            InteractionScope::Global,
        );
    }

    #[test]
    fn test_byte_lookup_interactions() {
        setup_logger();
        let program = sha_extend_program();
        let program_clone = program.clone();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        let machine = RiscvAir::machine(BabyBearPoseidon2::new());
        let (pkey, _) = machine.setup(&program_clone);
        let opts = SP1CoreOpts::default();
        machine.generate_dependencies(&mut runtime.records, &opts);

        let shards = runtime.records;
        assert_eq!(shards.len(), 2);
        for shard in shards.clone() {
            debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
                &machine,
                &pkey,
                &[shard],
                vec![InteractionKind::Memory],
                InteractionScope::Local,
            );
        }
        debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
            &machine,
            &pkey,
            &shards,
            vec![InteractionKind::Byte],
            InteractionScope::Global,
        );
    }
}
