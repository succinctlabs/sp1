#![allow(clippy::needless_range_loop)]

use core::borrow::Borrow;
use itertools::Itertools;
use sp1_core_machine::utils::pad_rows_fixed;
use sp1_stark::air::{BaseAirBuilder, BinomialExtension, MachineAir};
use std::borrow::BorrowMut;
use tracing::instrument;

use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_stark::air::ExtensionAirBuilder;

use sp1_derive::AlignedBorrow;

use crate::{
    air::Block,
    builder::SP1RecursionAirBuilder,
    runtime::{Instruction, RecursionProgram},
    Address, BatchFRIInstr, ExecutionRecord,
};

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

                row_add.iter_mut().enumerate().for_each(|(i, row)| {
                    let row: &mut BatchFRIPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                    row.is_real = F::one();
                    row.is_end = F::from_bool(i == len - 1);
                    row.acc_addr = ext_single_addrs.acc;
                    row.alpha_pow_addr = ext_vec_addrs.alpha_pow[i];
                    row.p_at_z_addr = ext_vec_addrs.p_at_z[i];
                    row.p_at_x_addr = base_vec_addrs.p_at_x[i];
                });
                rows.extend(row_add);
            });

        // Pad the trace to a power of two.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_BATCH_FRI_PREPROCESSED_COLS],
            program.fixed_log2_rows(self),
        );

        let trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_BATCH_FRI_PREPROCESSED_COLS,
        );
        Some(trace)
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
        pad_rows_fixed(&mut rows, || [F::zero(); NUM_BATCH_FRI_COLS], input.fixed_log2_rows(self));

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
