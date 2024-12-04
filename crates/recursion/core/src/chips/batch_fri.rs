#![allow(clippy::needless_range_loop)]

use crate::{
    air::Block,
    builder::SP1RecursionAirBuilder,
    runtime::{Instruction, RecursionProgram},
    Address, BatchFRIInstr, ExecutionRecord,
};
use core::borrow::Borrow;
use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_machine::utils::next_power_of_two;
use sp1_derive::AlignedBorrow;
use sp1_stark::air::ExtensionAirBuilder;
use sp1_stark::air::{BaseAirBuilder, BinomialExtension, MachineAir};
use std::borrow::BorrowMut;
use tracing::instrument;

pub const NUM_BATCH_FRI_COLS: usize = core::mem::size_of::<BatchFRICols<u8>>();
pub const NUM_BATCH_FRI_PREPROCESSED_COLS: usize =
    core::mem::size_of::<BatchFRIPreprocessedCols<u8>>();

#[derive(Clone, Debug, Copy, Default)]
pub struct BatchFRIChip<const DEGREE: usize>;

/// The preprocessed columns for a batch FRI invocation.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BatchFRIPreprocessedCols<T: Copy> {
    pub is_real: T,
    pub is_end: T,
    pub acc_addr: Address<T>,
    pub alpha_pow_addr: Address<T>,
    pub p_at_z_addr: Address<T>,
    pub p_at_x_addr: Address<T>,
}

/// The main columns for a batch FRI invocation.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BatchFRICols<T: Copy> {
    pub acc: Block<T>,
    pub alpha_pow: Block<T>,
    pub p_at_z: Block<T>,
    pub p_at_x: T,
}

impl<F, const DEGREE: usize> BaseAir<F> for BatchFRIChip<DEGREE> {
    fn width(&self) -> usize {
        NUM_BATCH_FRI_COLS
    }
}

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for BatchFRIChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "BatchFRI".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BATCH_FRI_PREPROCESSED_COLS
    }

    fn preprocessed_num_rows(&self, program: &Self::Program, instrs_len: usize) -> Option<usize> {
        Some(next_power_of_two(instrs_len, program.fixed_log2_rows(self)))
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_BATCH_FRI_PREPROCESSED_COLS]> = Vec::new();
        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::BatchFRI(instr) = instruction {
                    Some(instr)
                } else {
                    None
                }
            })
            .for_each(|instruction| {
                let BatchFRIInstr { base_vec_addrs, ext_single_addrs, ext_vec_addrs, acc_mult } =
                    instruction.as_ref();
                let len = ext_vec_addrs.p_at_z.len();
                let mut row_add = vec![[F::zero(); NUM_BATCH_FRI_PREPROCESSED_COLS]; len];
                debug_assert_eq!(*acc_mult, F::one());

                row_add.iter_mut().enumerate().for_each(|(_i, row)| {
                    let row: &mut BatchFRIPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                    row.is_real = F::one();
                    row.is_end = F::from_bool(_i == len - 1);
                    row.acc_addr = ext_single_addrs.acc;
                    row.alpha_pow_addr = ext_vec_addrs.alpha_pow[_i];
                    row.p_at_z_addr = ext_vec_addrs.p_at_z[_i];
                    row.p_at_x_addr = base_vec_addrs.p_at_x[_i];
                });
                rows.extend(row_add);
            });

        // Pad the trace to a power of two.
        rows.resize(
            self.preprocessed_num_rows(program, rows.len()).unwrap(),
            [F::zero(); NUM_BATCH_FRI_PREPROCESSED_COLS],
        );

        let trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_BATCH_FRI_PREPROCESSED_COLS,
        );
        Some(trace)
    }

    fn num_rows(&self, input: &Self::Record) -> usize {
        let events = &input.batch_fri_events;
        next_power_of_two(events.len(), input.fixed_log2_rows(self))
    }

    #[instrument(name = "generate batch fri trace", level = "debug", skip_all, fields(rows = input.batch_fri_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut rows = input
            .batch_fri_events
            .iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_BATCH_FRI_COLS];
                let cols: &mut BatchFRICols<F> = row.as_mut_slice().borrow_mut();
                cols.acc = event.ext_single.acc;
                cols.alpha_pow = event.ext_vec.alpha_pow;
                cols.p_at_z = event.ext_vec.p_at_z;
                cols.p_at_x = event.base_vec.p_at_x;
                row
            })
            .collect_vec();

        // Pad the trace to a power of two.
        rows.resize(self.num_rows(input), [F::zero(); NUM_BATCH_FRI_COLS]);

        // Convert the trace to a row major matrix.
        let trace = RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_BATCH_FRI_COLS);

        #[cfg(debug_assertions)]
        println!(
            "batch fri trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        trace
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<const DEGREE: usize> BatchFRIChip<DEGREE> {
    pub fn eval_batch_fri<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local: &BatchFRICols<AB::Var>,
        next: &BatchFRICols<AB::Var>,
        local_prepr: &BatchFRIPreprocessedCols<AB::Var>,
        _next_prepr: &BatchFRIPreprocessedCols<AB::Var>,
    ) {
        // Constrain memory read for alpha_pow, p_at_z, and p_at_x.
        builder.receive_block(local_prepr.alpha_pow_addr, local.alpha_pow, local_prepr.is_real);
        builder.receive_block(local_prepr.p_at_z_addr, local.p_at_z, local_prepr.is_real);
        builder.receive_single(local_prepr.p_at_x_addr, local.p_at_x, local_prepr.is_real);

        // Constrain memory write for the accumulator.
        // Note that we write with multiplicity 1, when `is_end` is true.
        builder.send_block(local_prepr.acc_addr, local.acc, local_prepr.is_end);

        // Constrain the accumulator value of the first row.
        builder.when_first_row().assert_ext_eq(
            local.acc.as_extension::<AB>(),
            local.alpha_pow.as_extension::<AB>()
                * (local.p_at_z.as_extension::<AB>()
                    - BinomialExtension::from_base(local.p_at_x.into())),
        );

        // Constrain the accumulator of the next row when the current row is the end of loop.
        builder.when_transition().when(local_prepr.is_end).assert_ext_eq(
            next.acc.as_extension::<AB>(),
            next.alpha_pow.as_extension::<AB>()
                * (next.p_at_z.as_extension::<AB>()
                    - BinomialExtension::from_base(next.p_at_x.into())),
        );

        // Constrain the accumulator of the next row when the current row is not the end of loop.
        builder.when_transition().when_not(local_prepr.is_end).assert_ext_eq(
            next.acc.as_extension::<AB>(),
            local.acc.as_extension::<AB>()
                + next.alpha_pow.as_extension::<AB>()
                    * (next.p_at_z.as_extension::<AB>()
                        - BinomialExtension::from_base(next.p_at_x.into())),
        );
    }

    pub const fn do_memory_access<T: Copy>(local: &BatchFRIPreprocessedCols<T>) -> T {
        local.is_real
    }
}

impl<AB, const DEGREE: usize> Air<AB> for BatchFRIChip<DEGREE>
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &BatchFRICols<AB::Var> = (*local).borrow();
        let next: &BatchFRICols<AB::Var> = (*next).borrow();
        let prepr = builder.preprocessed();
        let (prepr_local, prepr_next) = (prepr.row_slice(0), prepr.row_slice(1));
        let prepr_local: &BatchFRIPreprocessedCols<AB::Var> = (*prepr_local).borrow();
        let prepr_next: &BatchFRIPreprocessedCols<AB::Var> = (*prepr_next).borrow();

        // Dummy constraints to normalize to DEGREE.
        let lhs = (0..DEGREE).map(|_| prepr_local.is_real.into()).product::<AB::Expr>();
        let rhs = (0..DEGREE).map(|_| prepr_local.is_real.into()).product::<AB::Expr>();
        builder.assert_eq(lhs, rhs);

        self.eval_batch_fri::<AB>(builder, local, next, prepr_local, prepr_next);
    }
}

#[cfg(test)]
pub mod test_fixtures {
    use crate::{BatchFRIBaseVecIo, BatchFRIEvent, BatchFRIExtSingleIo, BatchFRIExtVecIo};
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;

    const SEED: u64 = 12345;
    const NUM_TEST_CASES: usize = 10000;

    pub fn sample_batch_fri_events() -> Vec<BatchFRIEvent<BabyBear>> {
        let mut events = Vec::with_capacity(NUM_TEST_CASES);

        for _ in 0..NUM_TEST_CASES {
            events.push(BatchFRIEvent {
                ext_single: BatchFRIExtSingleIo { acc: Block::default() },
                ext_vec: BatchFRIExtVecIo { alpha_pow: Block::default(), p_at_z: Block::default() },
                base_vec: BatchFRIBaseVecIo { p_at_x: BabyBear::one() },
            });
        }
        events
    }

    pub fn sample_batch_fri_instructions() -> Vec<Instruction<BabyBear>> {
        let mut rng = StdRng::seed_from_u64(SEED);
        let mut instructions = Vec::with_capacity(NUM_TEST_CASES);

        for _ in 0..NUM_TEST_CASES {
            let len = rng.gen_range(1..5); // Random number of addresses in vectors

            let p_at_x = (0..len).map(|_| Address(BabyBear::from_wrapped_u32(rng.gen()))).collect();
            let alpha_pow =
                (0..len).map(|_| Address(BabyBear::from_wrapped_u32(rng.gen()))).collect();
            let p_at_z = (0..len).map(|_| Address(BabyBear::from_wrapped_u32(rng.gen()))).collect();
            let acc = Address(BabyBear::from_wrapped_u32(rng.gen()));

            instructions.push(Instruction::BatchFRI(Box::new(BatchFRIInstr {
                base_vec_addrs: BatchFRIBaseVecIo { p_at_x },
                ext_single_addrs: BatchFRIExtSingleIo { acc },
                ext_vec_addrs: BatchFRIExtVecIo { alpha_pow, p_at_z },
                acc_mult: BabyBear::one(), // BatchFRI always uses mult of 1
            })));
        }
        instructions
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;

    const DEGREE: usize = 2;

    fn generate_trace_ffi<const DEGREE: usize>(
        input: &ExecutionRecord<BabyBear>,
    ) -> RowMajorMatrix<BabyBear> {
        type F = BabyBear;

        let events = &input.batch_fri_events;
        let mut rows = vec![[F::zero(); NUM_BATCH_FRI_COLS]; events.len()];

        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);
        rows.chunks_mut(chunk_size).enumerate().for_each(|(i, chunk)| {
            chunk.iter_mut().enumerate().for_each(|(j, row)| {
                let idx = i * chunk_size + j;
                if idx < events.len() {
                    let cols: &mut BatchFRICols<F> = row.as_mut_slice().borrow_mut();
                    unsafe {
                        crate::sys::batch_fri_event_to_row_babybear(&events[idx], cols);
                    }
                }
            });
        });

        rows.resize(BatchFRIChip::<DEGREE>.num_rows(input), [F::zero(); NUM_BATCH_FRI_COLS]);

        RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_BATCH_FRI_COLS)
    }

    #[test]
    fn generate_trace() {
        type F = BabyBear;

        let shard = ExecutionRecord {
            batch_fri_events: test_fixtures::sample_batch_fri_events(),
            ..Default::default()
        };
        let trace: RowMajorMatrix<F> =
            BatchFRIChip::<DEGREE>.generate_trace(&shard, &mut ExecutionRecord::default());

        assert_eq!(trace, generate_trace_ffi::<DEGREE>(&shard));
    }

    // fn generate_preprocessed_trace_ffi<const DEGREE: usize>(
    //     program: &RecursionProgram<BabyBear>,
    // ) -> RowMajorMatrix<BabyBear> {
    //     type F = BabyBear;

    //     let mut rows = Vec::new();
    //     extract_batch_fri_instrs(program).iter().for_each(|instruction| {
    //         let BatchFRIInstr { base_vec_addrs: _, ext_single_addrs: _, ext_vec_addrs, acc_mult } =
    //             instruction.as_ref();
    //         let len = ext_vec_addrs.p_at_z.len();
    //         let mut row_add = vec![[F::zero(); NUM_BATCH_FRI_PREPROCESSED_COLS]; len];
    //         debug_assert_eq!(*acc_mult, F::one());

    //         row_add.iter_mut().for_each(|row| {
    //             let cols: &mut BatchFRIPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
    //             unsafe {
    //                 crate::sys::batch_fri_instr_to_row_babybear(&instruction.into(), cols);
    //             }
    //         });
    //         rows.extend(row_add);
    //     });

    //     rows.resize(
    //         BatchFRIChip::<DEGREE>.preprocessed_num_rows(program, rows.len()).unwrap(),
    //         [F::zero(); NUM_BATCH_FRI_PREPROCESSED_COLS],
    //     );

    //     RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_BATCH_FRI_PREPROCESSED_COLS)
    // }

    // #[test]
    // fn generate_preprocessed_trace() {
    //     type F = BabyBear;

    //     let program = RecursionProgram::<F> {
    //         instructions: test_fixtures::sample_batch_fri_instructions(),
    //         ..Default::default()
    //     };
    //     let trace = BatchFRIChip::<DEGREE>.generate_preprocessed_trace(&program).unwrap();

    //     assert_eq!(trace, generate_preprocessed_trace_ffi::<DEGREE>(&program));
    // }
}
