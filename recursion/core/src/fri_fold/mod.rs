#![allow(clippy::needless_range_loop)]

use crate::memory::{MemoryReadCols, MemoryReadSingleCols, MemoryReadWriteCols};
use crate::runtime::Opcode;
use core::borrow::Borrow;
use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::{BaseAirBuilder, BinomialExtension, MachineAir};
use sp1_core::utils::pad_rows_fixed;
use sp1_derive::AlignedBorrow;
use std::borrow::BorrowMut;
use tracing::instrument;

use crate::air::SP1RecursionAirBuilder;
use crate::memory::MemoryRecord;
use crate::runtime::{ExecutionRecord, RecursionProgram};

pub const NUM_FRI_FOLD_COLS: usize = core::mem::size_of::<FriFoldCols<u8>>();

#[derive(Default)]
pub struct FriFoldChip<const DEGREE: usize> {
    pub fixed_log2_rows: Option<usize>,
    pub pad: bool,
}

#[derive(Debug, Clone)]
pub struct FriFoldEvent<F> {
    pub clk: F,
    pub m: F,
    pub input_ptr: F,
    pub is_last_iteration: F,

    pub z: MemoryRecord<F>,
    pub alpha: MemoryRecord<F>,
    pub x: MemoryRecord<F>,
    pub log_height: MemoryRecord<F>,
    pub mat_opening_ptr: MemoryRecord<F>,
    pub ps_at_z_ptr: MemoryRecord<F>,
    pub alpha_pow_ptr: MemoryRecord<F>,
    pub ro_ptr: MemoryRecord<F>,

    pub p_at_x: MemoryRecord<F>,
    pub p_at_z: MemoryRecord<F>,

    pub alpha_pow_at_log_height: MemoryRecord<F>,
    pub ro_at_log_height: MemoryRecord<F>,
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct FriFoldCols<T: Copy> {
    pub clk: T,

    /// The parameters into the FRI fold precompile.  These values are only read from memory.
    pub m: T,
    pub input_ptr: T,

    /// At the last iteraction of a FRI_FOLD invocation.
    pub is_last_iteration: T,

    /// The inputs stored in memory.  All the values are just read from memory.
    pub z: MemoryReadCols<T>,
    pub alpha: MemoryReadCols<T>,
    pub x: MemoryReadSingleCols<T>,

    pub log_height: MemoryReadSingleCols<T>,
    pub mat_opening_ptr: MemoryReadSingleCols<T>,
    pub ps_at_z_ptr: MemoryReadSingleCols<T>,
    pub alpha_pow_ptr: MemoryReadSingleCols<T>,
    pub ro_ptr: MemoryReadSingleCols<T>,

    pub p_at_x: MemoryReadCols<T>,
    pub p_at_z: MemoryReadCols<T>,

    /// The values here are read and then written.
    pub alpha_pow_at_log_height: MemoryReadWriteCols<T>,
    pub ro_at_log_height: MemoryReadWriteCols<T>,

    pub is_real: T,
}

impl<F, const DEGREE: usize> BaseAir<F> for FriFoldChip<DEGREE> {
    fn width(&self) -> usize {
        NUM_FRI_FOLD_COLS
    }
}

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for FriFoldChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "FriFold".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    #[instrument(name = "generate fri fold trace", level = "debug", skip_all, fields(rows = input.fri_fold_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut rows = input
            .fri_fold_events
            .iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_FRI_FOLD_COLS];

                let cols: &mut FriFoldCols<F> = row.as_mut_slice().borrow_mut();

                cols.clk = event.clk;
                cols.m = event.m;
                cols.input_ptr = event.input_ptr;
                cols.is_last_iteration = event.is_last_iteration;
                cols.is_real = F::one();

                cols.z.populate(&event.z);
                cols.alpha.populate(&event.alpha);
                cols.x.populate(&event.x);
                cols.log_height.populate(&event.log_height);
                cols.mat_opening_ptr.populate(&event.mat_opening_ptr);
                cols.ps_at_z_ptr.populate(&event.ps_at_z_ptr);
                cols.alpha_pow_ptr.populate(&event.alpha_pow_ptr);
                cols.ro_ptr.populate(&event.ro_ptr);

                cols.p_at_x.populate(&event.p_at_x);
                cols.p_at_z.populate(&event.p_at_z);

                cols.alpha_pow_at_log_height
                    .populate(&event.alpha_pow_at_log_height);
                cols.ro_at_log_height.populate(&event.ro_at_log_height);

                row
            })
            .collect_vec();

        // Pad the trace to a power of two.
        if self.pad {
            pad_rows_fixed(
                &mut rows,
                || [F::zero(); NUM_FRI_FOLD_COLS],
                self.fixed_log2_rows,
            );
        }

        // Convert the trace to a row major matrix.
        let trace = RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_FRI_FOLD_COLS);

        #[cfg(debug_assertions)]
        println!(
            "fri fold trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        trace
    }

    fn included(&self, record: &Self::Record) -> bool {
        !record.fri_fold_events.is_empty()
    }
}

impl<const DEGREE: usize> FriFoldChip<DEGREE> {
    pub fn eval_fri_fold<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local: &FriFoldCols<AB::Var>,
        next: &FriFoldCols<AB::Var>,
        receive_table: AB::Var,
        memory_access: AB::Var,
    ) {
        // Constraint that the operands are sent from the CPU table.
        let first_iteration_clk = local.clk.into() - local.m.into();
        let total_num_iterations = local.m.into() + AB::Expr::one();
        let operands = [
            first_iteration_clk,
            total_num_iterations,
            local.input_ptr.into(),
            AB::Expr::zero(),
        ];
        builder.receive_table(
            Opcode::FRIFold.as_field::<AB::F>(),
            &operands,
            receive_table,
        );

        builder.assert_bool(local.is_last_iteration);
        builder.assert_bool(local.is_real);

        builder
            .when_transition()
            .when_not(local.is_last_iteration)
            .assert_eq(local.is_real, next.is_real);

        builder
            .when(local.is_last_iteration)
            .assert_one(local.is_real);

        builder
            .when_transition()
            .when_not(local.is_real)
            .assert_zero(next.is_real);

        builder
            .when_last_row()
            .when_not(local.is_last_iteration)
            .assert_zero(local.is_real);

        // Ensure that all first iteration rows has a m value of 0.
        builder.when_first_row().assert_zero(local.m);
        builder
            .when(local.is_last_iteration)
            .when_transition()
            .when(next.is_real)
            .assert_zero(next.m);

        // Ensure that all rows for a FRI FOLD invocation have the same input_ptr and sequential clk and m values.
        builder
            .when_transition()
            .when_not(local.is_last_iteration)
            .when(next.is_real)
            .assert_eq(next.m, local.m + AB::Expr::one());
        builder
            .when_transition()
            .when_not(local.is_last_iteration)
            .when(next.is_real)
            .assert_eq(local.input_ptr, next.input_ptr);
        builder
            .when_transition()
            .when_not(local.is_last_iteration)
            .when(next.is_real)
            .assert_eq(local.clk + AB::Expr::one(), next.clk);

        // Constrain read for `z` at `input_ptr`
        builder.recursion_eval_memory_access(
            local.clk,
            local.input_ptr + AB::Expr::zero(),
            &local.z,
            memory_access,
        );

        // Constrain read for `alpha`
        builder.recursion_eval_memory_access(
            local.clk,
            local.input_ptr + AB::Expr::one(),
            &local.alpha,
            memory_access,
        );

        // Constrain read for `x`
        builder.recursion_eval_memory_access_single(
            local.clk,
            local.input_ptr + AB::Expr::from_canonical_u32(2),
            &local.x,
            memory_access,
        );

        // Constrain read for `log_height`
        builder.recursion_eval_memory_access_single(
            local.clk,
            local.input_ptr + AB::Expr::from_canonical_u32(3),
            &local.log_height,
            memory_access,
        );

        // Constrain read for `mat_opening_ptr`
        builder.recursion_eval_memory_access_single(
            local.clk,
            local.input_ptr + AB::Expr::from_canonical_u32(4),
            &local.mat_opening_ptr,
            memory_access,
        );

        // Constrain read for `ps_at_z_ptr`
        builder.recursion_eval_memory_access_single(
            local.clk,
            local.input_ptr + AB::Expr::from_canonical_u32(6),
            &local.ps_at_z_ptr,
            memory_access,
        );

        // Constrain read for `alpha_pow_ptr`
        builder.recursion_eval_memory_access_single(
            local.clk,
            local.input_ptr + AB::Expr::from_canonical_u32(8),
            &local.alpha_pow_ptr,
            memory_access,
        );

        // Constrain read for `ro_ptr`
        builder.recursion_eval_memory_access_single(
            local.clk,
            local.input_ptr + AB::Expr::from_canonical_u32(10),
            &local.ro_ptr,
            memory_access,
        );

        // Constrain read for `p_at_x`
        builder.recursion_eval_memory_access(
            local.clk,
            local.mat_opening_ptr.access.value.into() + local.m.into(),
            &local.p_at_x,
            memory_access,
        );

        // Constrain read for `p_at_z`
        builder.recursion_eval_memory_access(
            local.clk,
            local.ps_at_z_ptr.access.value.into() + local.m.into(),
            &local.p_at_z,
            memory_access,
        );

        // Update alpha_pow_at_log_height.
        // 1. Constrain old and new value against memory
        builder.recursion_eval_memory_access(
            local.clk,
            local.alpha_pow_ptr.access.value.into() + local.log_height.access.value.into(),
            &local.alpha_pow_at_log_height,
            memory_access,
        );

        // 2. Constrain new_value = old_value * alpha.
        let alpha = local.alpha.access.value.as_extension::<AB>();
        let alpha_pow_at_log_height = local
            .alpha_pow_at_log_height
            .prev_value
            .as_extension::<AB>();
        let new_alpha_pow_at_log_height = local
            .alpha_pow_at_log_height
            .access
            .value
            .as_extension::<AB>();

        builder.assert_ext_eq(
            alpha_pow_at_log_height.clone() * alpha,
            new_alpha_pow_at_log_height,
        );

        // Update ro_at_log_height.
        // 1. Constrain old and new value against memory.
        builder.recursion_eval_memory_access(
            local.clk,
            local.ro_ptr.access.value.into() + local.log_height.access.value.into(),
            &local.ro_at_log_height,
            memory_access,
        );

        // 2. Constrain new_value = old_alpha_pow_at_log_height * quotient + old_value,
        // where quotient = (p_at_x - p_at_z) / (x - z)
        // <=> (new_value - old_value) * (z - x) = old_alpha_pow_at_log_height * (p_at_x - p_at_z)
        let p_at_z = local.p_at_z.access.value.as_extension::<AB>();
        let p_at_x = local.p_at_x.access.value.as_extension::<AB>();
        let z = local.z.access.value.as_extension::<AB>();
        let x = local.x.access.value.into();

        let ro_at_log_height = local.ro_at_log_height.prev_value.as_extension::<AB>();
        let new_ro_at_log_height = local.ro_at_log_height.access.value.as_extension::<AB>();
        builder.assert_ext_eq(
            (new_ro_at_log_height - ro_at_log_height) * (BinomialExtension::from_base(x) - z),
            (p_at_x - p_at_z) * alpha_pow_at_log_height,
        );
    }

    pub const fn do_receive_table<T: Copy>(local: &FriFoldCols<T>) -> T {
        local.is_last_iteration
    }

    pub const fn do_memory_access<T: Copy>(local: &FriFoldCols<T>) -> T {
        local.is_real
    }
}

impl<AB, const DEGREE: usize> Air<AB> for FriFoldChip<DEGREE>
where
    AB: SP1RecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &FriFoldCols<AB::Var> = (*local).borrow();
        let next: &FriFoldCols<AB::Var> = (*next).borrow();

        // Dummy constraints to normalize to DEGREE.
        let lhs = (0..DEGREE)
            .map(|_| local.is_real.into())
            .product::<AB::Expr>();
        let rhs = (0..DEGREE)
            .map(|_| local.is_real.into())
            .product::<AB::Expr>();
        builder.assert_eq(lhs, rhs);

        self.eval_fri_fold::<AB>(
            builder,
            local,
            next,
            Self::do_receive_table::<AB::Var>(local),
            Self::do_memory_access::<AB::Var>(local),
        );
    }
}
