#![allow(clippy::needless_range_loop)]

use core::borrow::Borrow;
use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::{AirInteraction, BinomialExtension, MachineAir, SP1AirBuilder};
use sp1_core::lookup::InteractionKind;
use sp1_core::utils::pad_to_power_of_two;
use sp1_derive::AlignedBorrow;
use std::borrow::BorrowMut;
use tracing::instrument;

use crate::memory::{MemoryReadWriteCols, MemoryRecord};
use crate::runtime::{ExecutionRecord, RecursionProgram};

pub const NUM_FRI_FOLD_COLS: usize = core::mem::size_of::<FriFoldCols<u8>>();

#[derive(Default)]
pub struct FriFoldChip;

#[derive(Debug, Clone)]
pub struct FriFoldEvent<F> {
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
    pub z: MemoryReadWriteCols<T>,
    pub alpha: MemoryReadWriteCols<T>,
    pub x: MemoryReadWriteCols<T>,
    pub log_height: MemoryReadWriteCols<T>,
    pub mat_opening_ptr: MemoryReadWriteCols<T>,
    pub ps_at_z_ptr: MemoryReadWriteCols<T>,
    pub alpha_pow_ptr: MemoryReadWriteCols<T>,
    pub ro_ptr: MemoryReadWriteCols<T>,

    pub p_at_x: MemoryReadWriteCols<T>,
    pub p_at_z: MemoryReadWriteCols<T>,

    /// The values here are read and then written.
    pub alpha_pow_at_log_height: MemoryReadWriteCols<T>,
    pub ro_at_log_height: MemoryReadWriteCols<T>,
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

                cols.m = event.m;
                cols.input_ptr = event.input_ptr;

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
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let cols = main.row_slice(0);
        let cols: &FriFoldCols<AB::Var> = (*cols).borrow();

        // TODO
        // Constrain `m`
        // Constrain `ptr`

        // Constrain read for `z`
        builder.receive(AirInteraction::new(
            vec![
                cols.z.addr.into(),
                cols.z.timestamp.into(),
                cols.z.prev_value.0[0].into(),
                cols.z.prev_value.0[1].into(),
                cols.z.prev_value.0[2].into(),
                cols.z.prev_value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));
        builder.send(AirInteraction::new(
            vec![
                cols.z.addr.into(),
                cols.z.timestamp.into(),
                cols.z.value.0[0].into(),
                cols.z.value.0[1].into(),
                cols.z.value.0[2].into(),
                cols.z.value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));

        // Constraintread for `alpha`
        builder.receive(AirInteraction::new(
            vec![
                cols.alpha.addr.into(),
                cols.alpha.timestamp.into(),
                cols.alpha.prev_value.0[0].into(),
                cols.alpha.prev_value.0[1].into(),
                cols.alpha.prev_value.0[2].into(),
                cols.alpha.prev_value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));
        builder.send(AirInteraction::new(
            vec![
                cols.alpha.addr.into(),
                cols.alpha.timestamp.into(),
                cols.alpha.value.0[0].into(),
                cols.alpha.value.0[1].into(),
                cols.alpha.value.0[2].into(),
                cols.alpha.value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));

        // Constrain read for `x`
        builder.receive(AirInteraction::new(
            vec![
                cols.x.addr.into(),
                cols.x.timestamp.into(),
                cols.x.prev_value.0[0].into(),
                cols.x.prev_value.0[1].into(),
                cols.x.prev_value.0[2].into(),
                cols.x.prev_value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));
        builder.send(AirInteraction::new(
            vec![
                cols.x.addr.into(),
                cols.x.timestamp.into(),
                cols.x.value.0[0].into(),
                cols.x.value.0[1].into(),
                cols.x.value.0[2].into(),
                cols.x.value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));

        // Constrain read for `log_height`
        builder.receive(AirInteraction::new(
            vec![
                cols.log_height.addr.into(),
                cols.log_height.timestamp.into(),
                cols.log_height.prev_value.0[0].into(),
                cols.log_height.prev_value.0[1].into(),
                cols.log_height.prev_value.0[2].into(),
                cols.log_height.prev_value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));
        builder.send(AirInteraction::new(
            vec![
                cols.log_height.addr.into(),
                cols.log_height.timestamp.into(),
                cols.log_height.value.0[0].into(),
                cols.log_height.value.0[1].into(),
                cols.log_height.value.0[2].into(),
                cols.log_height.value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));

        // Constrain read for `mat_opening_ptr`
        builder.receive(AirInteraction::new(
            vec![
                cols.mat_opening_ptr.addr.into(),
                cols.mat_opening_ptr.timestamp.into(),
                cols.mat_opening_ptr.prev_value.0[0].into(),
                cols.mat_opening_ptr.prev_value.0[1].into(),
                cols.mat_opening_ptr.prev_value.0[2].into(),
                cols.mat_opening_ptr.prev_value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));
        builder.send(AirInteraction::new(
            vec![
                cols.mat_opening_ptr.addr.into(),
                cols.mat_opening_ptr.timestamp.into(),
                cols.mat_opening_ptr.value.0[0].into(),
                cols.mat_opening_ptr.value.0[1].into(),
                cols.mat_opening_ptr.value.0[2].into(),
                cols.mat_opening_ptr.value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));

        // Constrain read for `ps_at_z_ptr`
        builder.receive(AirInteraction::new(
            vec![
                cols.ps_at_z_ptr.addr.into(),
                cols.ps_at_z_ptr.timestamp.into(),
                cols.ps_at_z_ptr.prev_value.0[0].into(),
                cols.ps_at_z_ptr.prev_value.0[1].into(),
                cols.ps_at_z_ptr.prev_value.0[2].into(),
                cols.ps_at_z_ptr.prev_value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));
        builder.send(AirInteraction::new(
            vec![
                cols.ps_at_z_ptr.addr.into(),
                cols.ps_at_z_ptr.timestamp.into(),
                cols.ps_at_z_ptr.value.0[0].into(),
                cols.ps_at_z_ptr.value.0[1].into(),
                cols.ps_at_z_ptr.value.0[2].into(),
                cols.ps_at_z_ptr.value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));

        // Constrain read for `alpha_pow_ptr`
        builder.receive(AirInteraction::new(
            vec![
                cols.alpha_pow_ptr.addr.into(),
                cols.alpha_pow_ptr.timestamp.into(),
                cols.alpha_pow_ptr.prev_value.0[0].into(),
                cols.alpha_pow_ptr.prev_value.0[1].into(),
                cols.alpha_pow_ptr.prev_value.0[2].into(),
                cols.alpha_pow_ptr.prev_value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));
        builder.send(AirInteraction::new(
            vec![
                cols.alpha_pow_ptr.addr.into(),
                cols.alpha_pow_ptr.timestamp.into(),
                cols.alpha_pow_ptr.value.0[0].into(),
                cols.alpha_pow_ptr.value.0[1].into(),
                cols.alpha_pow_ptr.value.0[2].into(),
                cols.alpha_pow_ptr.value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));

        // Constrain read for `ro_ptr`
        builder.receive(AirInteraction::new(
            vec![
                cols.ro_ptr.addr.into(),
                cols.ro_ptr.timestamp.into(),
                cols.ro_ptr.prev_value.0[0].into(),
                cols.ro_ptr.prev_value.0[1].into(),
                cols.ro_ptr.prev_value.0[2].into(),
                cols.ro_ptr.prev_value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));
        builder.send(AirInteraction::new(
            vec![
                cols.ro_ptr.addr.into(),
                cols.ro_ptr.timestamp.into(),
                cols.ro_ptr.value.0[0].into(),
                cols.ro_ptr.value.0[1].into(),
                cols.ro_ptr.value.0[2].into(),
                cols.ro_ptr.value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));

        // Constrain read for `p_at_x`
        builder.receive(AirInteraction::new(
            vec![
                cols.p_at_x.addr.into(),
                cols.p_at_x.timestamp.into(),
                cols.p_at_x.prev_value.0[0].into(),
                cols.p_at_x.prev_value.0[1].into(),
                cols.p_at_x.prev_value.0[2].into(),
                cols.p_at_x.prev_value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));
        builder.send(AirInteraction::new(
            vec![
                cols.p_at_x.addr.into(),
                cols.p_at_x.timestamp.into(),
                cols.p_at_x.value.0[0].into(),
                cols.p_at_x.value.0[1].into(),
                cols.p_at_x.value.0[2].into(),
                cols.p_at_x.value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));

        // Constrain read for `p_at_z`
        builder.receive(AirInteraction::new(
            vec![
                cols.p_at_z.addr.into(),
                cols.p_at_z.timestamp.into(),
                cols.p_at_z.prev_value.0[0].into(),
                cols.p_at_z.prev_value.0[1].into(),
                cols.p_at_z.prev_value.0[2].into(),
                cols.p_at_z.prev_value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));
        builder.send(AirInteraction::new(
            vec![
                cols.p_at_z.addr.into(),
                cols.p_at_z.timestamp.into(),
                cols.p_at_z.value.0[0].into(),
                cols.p_at_z.value.0[1].into(),
                cols.p_at_z.value.0[2].into(),
                cols.p_at_z.value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));

        // Update alpha_pow_at_log_height
        // 1. constrain old and new value against memory
        builder.receive(AirInteraction::new(
            vec![
                cols.alpha_pow_at_log_height.addr.into(),
                cols.alpha_pow_at_log_height.timestamp.into(),
                cols.alpha_pow_at_log_height.prev_value.0[0].into(),
                cols.alpha_pow_at_log_height.prev_value.0[1].into(),
                cols.alpha_pow_at_log_height.prev_value.0[2].into(),
                cols.alpha_pow_at_log_height.prev_value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));
        builder.send(AirInteraction::new(
            vec![
                cols.alpha_pow_at_log_height.addr.into(),
                cols.alpha_pow_at_log_height.timestamp.into(),
                cols.alpha_pow_at_log_height.value.0[0].into(),
                cols.alpha_pow_at_log_height.value.0[1].into(),
                cols.alpha_pow_at_log_height.value.0[2].into(),
                cols.alpha_pow_at_log_height.value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));

        // 2. constrain new_value = old_value * alpha
        let alpha = cols.alpha.value.as_extension::<AB>();
        let alpha_pow_at_log_height = cols.alpha_pow_at_log_height.prev_value.as_extension::<AB>();
        let new_alpha_pow_at_log_height = cols.alpha_pow_at_log_height.value.as_extension::<AB>();
        builder.assert_ext_eq(
            alpha_pow_at_log_height.clone() * alpha,
            new_alpha_pow_at_log_height,
        );

        // Update ro_at_log_height
        // 1. constrain old and new value against memory
        builder.receive(AirInteraction::new(
            vec![
                cols.ro_at_log_height.addr.into(),
                cols.ro_at_log_height.timestamp.into(),
                cols.ro_at_log_height.prev_value.0[0].into(),
                cols.ro_at_log_height.prev_value.0[1].into(),
                cols.ro_at_log_height.prev_value.0[2].into(),
                cols.ro_at_log_height.prev_value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));
        builder.send(AirInteraction::new(
            vec![
                cols.ro_at_log_height.addr.into(),
                cols.ro_at_log_height.timestamp.into(),
                cols.ro_at_log_height.value.0[0].into(),
                cols.ro_at_log_height.value.0[1].into(),
                cols.ro_at_log_height.value.0[2].into(),
                cols.ro_at_log_height.value.0[3].into(),
            ],
            AB::Expr::zero(),
            InteractionKind::Memory,
        ));

        // 2. constrain new_value = old_alpha_pow_at_log_height * quotient + old_value
        // where quotient = (p_at_x - p_at_z) / (x - z);
        // <=> (new_value - old_value) * (z - x) = old_alpha_pow_at_log_height * (p_at_x - p_at_z)
        let p_at_z = cols.p_at_z.value.as_extension::<AB>();
        let p_at_x = cols.p_at_x.value.as_extension::<AB>();
        let z = cols.z.value.as_extension::<AB>();
        let x = cols.x.value[0].into();

        let ro_at_log_height = cols.ro_at_log_height.prev_value.as_extension::<AB>();
        let new_ro_at_log_height = cols.ro_at_log_height.value.as_extension::<AB>();
        builder.assert_ext_eq(
            (new_ro_at_log_height - ro_at_log_height) * (BinomialExtension::from_base(x) - z),
            (p_at_x - p_at_z) * alpha_pow_at_log_height,
        );
    }
}
