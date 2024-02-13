use crate::air::MachineAir;
use crate::air::{AirInteraction, CurtaAirBuilder, Word};
use crate::utils::pad_to_power_of_two;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::runtime::ExecutionRecord;
use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};
use curta_derive::AlignedBorrow;
use p3_air::Air;
use p3_air::BaseAir;
use p3_field::AbstractField;
use p3_matrix::MatrixRowSlices;
use p3_util::indices_arr;

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
    fn name(&self) -> String {
        match self.kind {
            MemoryChipKind::Init => "MemoryInit".to_string(),
            MemoryChipKind::Finalize => "MemoryFinalize".to_string(),
            MemoryChipKind::Program => "MemoryProgram".to_string(),
        }
    }

    fn shard(&self, input: &ExecutionRecord, output: &mut Vec<ExecutionRecord>) {
        let last = output.last_mut().unwrap();
        match self.kind {
            MemoryChipKind::Init => {
                last.first_memory_record = input.first_memory_record.clone();
            }
            MemoryChipKind::Finalize => {
                last.last_memory_record = input.last_memory_record.clone();
            }
            MemoryChipKind::Program => {
                last.program_memory_record = input.program_memory_record.clone();
            }
        }
    }

    fn include(&self, reccord: &ExecutionRecord) -> bool {
        match self.kind {
            MemoryChipKind::Init => !reccord.first_memory_record.is_empty(),
            MemoryChipKind::Finalize => !reccord.last_memory_record.is_empty(),
            MemoryChipKind::Program => !reccord.program_memory_record.is_empty(),
        }
    }

    fn generate_trace(&self, record: &mut ExecutionRecord) -> RowMajorMatrix<F> {
        let memory_record = match self.kind {
            MemoryChipKind::Init => &record.first_memory_record,
            MemoryChipKind::Finalize => &record.last_memory_record,
            MemoryChipKind::Program => &record.program_memory_record,
        };
        let rows: Vec<[F; 8]> = (0..memory_record.len()) // TODO: change this back to par_iter
            .map(|i| {
                let (addr, record, multiplicity) = memory_record[i];
                let mut row = [F::zero(); NUM_MEMORY_INIT_COLS];
                let cols: &mut MemoryInitCols<F> = row.as_mut_slice().borrow_mut();
                cols.addr = F::from_canonical_u32(addr);
                cols.shard = F::from_canonical_u32(record.shard);
                cols.timestamp = F::from_canonical_u32(record.timestamp);
                cols.value = record.value.into();
                cols.is_real = F::from_canonical_u32(multiplicity);
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
    AB: CurtaAirBuilder,
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

#[cfg(test)]
mod tests {

    use crate::lookup::{debug_interactions_with_all_chips, InteractionKind};
    use crate::memory::MemoryGlobalChip;
    use crate::stark::RiscvStark;
    use crate::syscall::precompiles::sha256::extend_tests::sha_extend_program;
    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::runtime::tests::simple_program;
    use crate::runtime::Runtime;
    use crate::utils::{setup_logger, BabyBearPoseidon2, StarkUtils};

    #[test]
    fn test_memory_generate_trace() {
        let program = simple_program();
        let mut runtime = Runtime::new(program);
        runtime.run();
        let mut shard = runtime.record.clone();

        let chip: MemoryGlobalChip = MemoryGlobalChip::new(MemoryChipKind::Init);

        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut shard);
        println!("{:?}", trace.values);

        let chip: MemoryGlobalChip = MemoryGlobalChip::new(MemoryChipKind::Finalize);
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut shard);
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

        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime.record);
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

        let machine = RiscvStark::new(BabyBearPoseidon2::new());
        debug_interactions_with_all_chips(
            &machine.chips(),
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

        let machine = RiscvStark::new(BabyBearPoseidon2::new());
        debug_interactions_with_all_chips(
            &machine.chips(),
            &runtime.record,
            vec![InteractionKind::Byte],
        );
    }
}
