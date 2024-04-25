#![allow(clippy::needless_range_loop)]

use crate::memory::{MemoryReadCols, MemoryReadSingleCols, MemoryReadWriteCols};
use crate::runtime::Opcode;
use core::borrow::Borrow;
use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::{BinomialExtension, MachineAir};
use sp1_core::utils::pad_to_power_of_two;
use sp1_derive::AlignedBorrow;
use std::borrow::BorrowMut;
use tracing::instrument;

use crate::air::SP1RecursionAirBuilder;
use crate::memory::MemoryRecord;
use crate::runtime::{ExecutionRecord, RecursionProgram};

pub const NUM_FRI_FOLD_COLS: usize = core::mem::size_of::<FriFoldCols<u8>>();

#[derive(Default)]
pub struct FriFoldChip;

#[derive(Debug, Clone)]
pub struct FriFoldEvent<F> {
    pub clk: F,
    pub m: F,
    pub input_ptr: F,

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

#[derive(AlignedBorrow, Debug, Clone)]
#[repr(C)]
pub struct FriFoldCols<T> {
    pub clk: T,

    /// The parameters into the FRI fold precompile.  These values are only read from memory.
    pub m: T,
    pub input_ptr: T,

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

impl<F> BaseAir<F> for FriFoldChip {
    fn width(&self) -> usize {
        NUM_FRI_FOLD_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for FriFoldChip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "FriFold".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    #[instrument(name = "generate fri fold trace", level = "debug", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let trace_values = input
            .fri_fold_events
            .iter()
            .flat_map(|event| {
                let mut row = [F::zero(); NUM_FRI_FOLD_COLS];

                let cols: &mut FriFoldCols<F> = row.as_mut_slice().borrow_mut();

                cols.clk = event.clk;
                cols.m = event.m;
                cols.input_ptr = event.input_ptr;
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

                row.into_iter()
            })
            .collect_vec();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(trace_values, NUM_FRI_FOLD_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_FRI_FOLD_COLS, F>(&mut trace.values);

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

impl<AB> Air<AB> for FriFoldChip
where
    AB: SP1RecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let cols = main.row_slice(0);
        let cols: &FriFoldCols<AB::Var> = (*cols).borrow();

        // Constraint that the operands are sent from the CPU table.
        let operands = [
            cols.clk.into(),
            cols.m.into(),
            cols.input_ptr.into(),
            AB::Expr::zero(),
        ];
        builder.receive_table(Opcode::FRIFold.as_field::<AB::F>(), &operands, cols.is_real);

        // Constrain read for `z` at `input_ptr`
        builder.recursion_eval_memory_access(
            cols.clk,
            cols.input_ptr + AB::Expr::zero(),
            &cols.z,
            cols.is_real,
        );

        // Constrain read for `alpha`
        builder.recursion_eval_memory_access(
            cols.clk,
            cols.input_ptr + AB::Expr::one(),
            &cols.alpha,
            cols.is_real,
        );

        // Constrain read for `x`
        builder.recursion_eval_memory_access_single(
            cols.clk,
            cols.input_ptr + AB::Expr::from_canonical_u32(2),
            &cols.x,
            cols.is_real,
        );

        // Constrain read for `log_height`
        builder.recursion_eval_memory_access_single(
            cols.clk,
            cols.input_ptr + AB::Expr::from_canonical_u32(3),
            &cols.log_height,
            cols.is_real,
        );

        // Constrain read for `mat_opening_ptr`
        builder.recursion_eval_memory_access_single(
            cols.clk,
            cols.input_ptr + AB::Expr::from_canonical_u32(4),
            &cols.mat_opening_ptr,
            cols.is_real,
        );

        // Constrain read for `ps_at_z_ptr`
        builder.recursion_eval_memory_access_single(
            cols.clk,
            cols.input_ptr + AB::Expr::from_canonical_u32(6),
            &cols.ps_at_z_ptr,
            cols.is_real,
        );

        // Constrain read for `alpha_pow_ptr`
        builder.recursion_eval_memory_access_single(
            cols.clk,
            cols.input_ptr + AB::Expr::from_canonical_u32(8),
            &cols.alpha_pow_ptr,
            cols.is_real,
        );

        // Constrain read for `ro_ptr`
        builder.recursion_eval_memory_access_single(
            cols.clk,
            cols.input_ptr + AB::Expr::from_canonical_u32(10),
            &cols.ro_ptr,
            cols.is_real,
        );

        // Constrain read for `p_at_x`
        builder.recursion_eval_memory_access(
            cols.clk,
            cols.mat_opening_ptr.access.value.into() + cols.m.into(),
            &cols.p_at_x,
            cols.is_real,
        );

        // Constrain read for `p_at_z`
        builder.recursion_eval_memory_access(
            cols.clk,
            cols.ps_at_z_ptr.access.value.into() + cols.m.into(),
            &cols.p_at_z,
            cols.is_real,
        );

        // Update alpha_pow_at_log_height.
        // 1. Constrain old and new value against memory
        builder.recursion_eval_memory_access(
            cols.clk,
            cols.alpha_pow_ptr.access.value.into() + cols.log_height.access.value.into(),
            &cols.alpha_pow_at_log_height,
            cols.is_real,
        );

        // 2. Constrain new_value = old_value * alpha.
        let alpha = cols.alpha.access.value.as_extension::<AB>();
        let alpha_pow_at_log_height = cols.alpha_pow_at_log_height.prev_value.as_extension::<AB>();
        let new_alpha_pow_at_log_height = cols
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
            cols.clk,
            cols.ro_ptr.access.value.into() + cols.log_height.access.value.into(),
            &cols.ro_at_log_height,
            cols.is_real,
        );

        // 2. Constrain new_value = old_alpha_pow_at_log_height * quotient + old_value,
        // where quotient = (p_at_x - p_at_z) / (x - z)
        // <=> (new_value - old_value) * (z - x) = old_alpha_pow_at_log_height * (p_at_x - p_at_z)
        let p_at_z = cols.p_at_z.access.value.as_extension::<AB>();
        let p_at_x = cols.p_at_x.access.value.as_extension::<AB>();
        let z = cols.z.access.value.as_extension::<AB>();
        let x = cols.x.access.value.into();

        let ro_at_log_height = cols.ro_at_log_height.prev_value.as_extension::<AB>();
        let new_ro_at_log_height = cols.ro_at_log_height.access.value.as_extension::<AB>();
        builder.assert_ext_eq(
            (new_ro_at_log_height - ro_at_log_height) * (BinomialExtension::from_base(x) - z),
            (p_at_x - p_at_z) * alpha_pow_at_log_height,
        );
    }
}
