use crate::air::MachineAir;
use crate::air::SP1AirBuilder;
use crate::cpu::MemoryWriteRecord;
use crate::field::event::FieldEvent;
use crate::memory::MemoryWriteCols;
use crate::operations::{AddOperation, XorOperation};
use crate::runtime::ExecutionRecord;
use crate::runtime::Syscall;
use crate::syscall::precompiles::SyscallContext;
use crate::utils::pad_rows;
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use sp1_derive::AlignedBorrow;
use std::fmt::Debug;
use tracing::instrument;

/// Elliptic curve add event.
#[derive(Debug, Clone, Copy)]
pub struct SimplePrecompileEvent {
    pub shard: u32,
    pub clk: u32,
    pub p_ptr: u32,
    pub p: [u32; 8],
    pub p_memory_records: [MemoryWriteRecord; 8],
}

pub const NUM_SIMPLE_PRECOMPILE_COLS: usize = size_of::<SimplePrecompileCols<u8>>();

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct SimplePrecompileCols<T> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub p_ptr: T,
    pub p_access: [MemoryWriteCols<T>; 8],
    pub(crate) p_0_plus_p_1: AddOperation<T>,
    pub(crate) p_2_plus_p_3: AddOperation<T>,
    pub(crate) p_4_xor_p_5: XorOperation<T>,
    pub(crate) p_6_xor_p_7: XorOperation<T>,
}

#[derive(Default)]
pub struct SimplePrecompileChip {}

impl SimplePrecompileChip {
    fn populate_operations<F: PrimeField32>(
        cols: &mut SimplePrecompileCols<F>,
        record: &mut ExecutionRecord,
        p: &[u32],
    ) {
        cols.p_0_plus_p_1.populate(record, p[0], p[1]);
        cols.p_2_plus_p_3.populate(record, p[2], p[3]);
        cols.p_4_xor_p_5.populate(record, p[4], p[5]);
        cols.p_6_xor_p_7.populate(record, p[6], p[7]);
    }
}

impl Syscall for SimplePrecompileChip {
    fn num_extra_cycles(&self) -> u32 {
        4
    }

    fn execute(&self, rt: &mut SyscallContext) -> u32 {
        let a0 = crate::runtime::Register::X10;
        let _a1 = crate::runtime::Register::X11;
        let start_clk = rt.clk;

        // TODO: we're making a new API for this
        let p_ptr = rt.register_unsafe(a0);
        if p_ptr % 4 != 0 {
            panic!();
        }

        let p_read = rt.slice_unsafe(p_ptr, 8);
        let p_final = [
            p_read[0] + p_read[1],
            p_read[2] + p_read[3],
            p_read[4] ^ p_read[5],
            p_read[6] ^ p_read[7],
            p_read[4],
            p_read[5],
            p_read[6],
            p_read[7],
        ];
        let p_records = rt.mw_slice(p_ptr, &p_final);
        rt.clk += 4;

        let event = SimplePrecompileEvent {
            shard: rt.current_shard(),
            clk: start_clk,
            p_ptr,
            p: p_read.try_into().unwrap(),
            p_memory_records: p_records.try_into().unwrap(),
        };

        rt.record_mut().simple_precompile_events.push(event);
        0 // TODO: we're going to remove this return value
    }
}

impl<F: PrimeField32> MachineAir<F> for SimplePrecompileChip {
    fn name(&self) -> String {
        "SimplePrecompile".to_string()
    }

    #[instrument(name = "generate simple precompile trace", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let (mut rows, new_field_events_list): (
            Vec<[F; NUM_SIMPLE_PRECOMPILE_COLS]>,
            Vec<Vec<FieldEvent>>,
        ) = input
            .simple_precompile_events
            .iter() // TODO: should be made a par_iter
            .map(|event| {
                let mut row = [F::zero(); NUM_SIMPLE_PRECOMPILE_COLS];
                let cols: &mut SimplePrecompileCols<F> = row.as_mut_slice().borrow_mut();

                // Decode affine points.
                let p = &event.p;

                // Populate basic columns.
                cols.is_real = F::one();
                cols.shard = F::from_canonical_u32(event.shard);
                cols.clk = F::from_canonical_u32(event.clk);
                cols.p_ptr = F::from_canonical_u32(event.p_ptr);

                Self::populate_operations(cols, output, p);

                // Populate the memory access columns.
                let mut new_field_events = Vec::new();
                for i in 0..8 {
                    cols.p_access[i].populate(event.p_memory_records[i], &mut new_field_events);
                }
                (row, new_field_events)
            })
            .unzip();

        for new_field_events in new_field_events_list {
            output.add_field_events(&new_field_events);
        }

        pad_rows(&mut rows, || {
            let row = [F::zero(); NUM_SIMPLE_PRECOMPILE_COLS];
            row
        });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SIMPLE_PRECOMPILE_COLS,
        )
    }
}

impl<F> BaseAir<F> for SimplePrecompileChip {
    fn width(&self) -> usize {
        NUM_SIMPLE_PRECOMPILE_COLS
    }
}

impl<AB> Air<AB> for SimplePrecompileChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row: &SimplePrecompileCols<AB::Var> = main.row_slice(0).borrow();

        AddOperation::<AB::F>::eval(
            builder,
            row.p_access[0].prev_value,
            row.p_access[1].prev_value,
            row.p_0_plus_p_1,
            row.is_real,
        );
        AddOperation::<AB::F>::eval(
            builder,
            row.p_access[2].prev_value,
            row.p_access[3].prev_value,
            row.p_2_plus_p_3,
            row.is_real,
        );
        XorOperation::<AB::F>::eval(
            builder,
            row.p_access[4].prev_value,
            row.p_access[5].prev_value,
            row.p_4_xor_p_5,
            row.is_real,
        );
        XorOperation::<AB::F>::eval(
            builder,
            row.p_access[6].prev_value,
            row.p_access[7].prev_value,
            row.p_6_xor_p_7,
            row.is_real,
        );

        for i in 0..8 {
            builder.constraint_memory_access(
                row.shard,
                row.clk, // clk + 0 -> Memory
                row.p_ptr + AB::F::from_canonical_u32(i * 4),
                &row.p_access[i as usize],
                row.is_real,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;

    use crate::runtime::{ExecutionRecord, Runtime};
    use crate::utils::run_test;
    use crate::utils::{self, tests::SIMPLE_PRECOMPILE_ELF};
    use crate::Program;

    #[test]
    fn generate_trace() {
        let program = Program::from(SIMPLE_PRECOMPILE_ELF);
        let mut runtime = Runtime::new(program);
        runtime.run();

        println!("{:?}", runtime.record.simple_precompile_events);

        let chip = SimplePrecompileChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&runtime.record, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn test_simple_precompile() {
        utils::setup_logger();
        let program = Program::from(SIMPLE_PRECOMPILE_ELF);
        run_test(program).unwrap();
    }
}
