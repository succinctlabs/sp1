#![allow(clippy::needless_range_loop)]

use core::borrow::Borrow;
use core::mem::size_of;
use p3_air::AirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::{MachineAir, SP1AirBuilder};
use sp1_core::utils::pad_to_power_of_two;
use sp1_derive::AlignedBorrow;
use std::borrow::BorrowMut;
use tracing::instrument;

use crate::air::Block;
use crate::runtime::{ExecutionRecord, RecursionProgram};

pub const NUM_FRI_FOLD_COLS: usize = 0;

#[derive(Default)]
pub struct FriFoldChip;

/// Event containing the inputs to a FRI fold operation.
#[derive(Debug, Clone)]
pub struct FriFoldEvent<F> {
    pub m: F,
    pub input_ptr: F,
}

#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct FriFoldCols<T> {
    pub m: T,
    pub input_ptr: T,

    pub z: Block<T>,
    pub alpha: Block<T>,

    pub x: T,

    pub p_at_x: Block<T>,
    pub p_at_z: Block<T>,

    pub alpha_pow_at_log_height: Block<T>,
    pub ro_at_log_height: Block<T>,

    pub quotient: Block<T>,
}

impl<F: PrimeField32> MachineAir<F> for FriFoldChip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "FriFold".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        todo!()
    }

    fn included(&self, record: &Self::Record) -> bool {
        !record.fri_fold_events.is_empty()
    }
}

impl<F> BaseAir<F> for FriFoldChip {
    fn width(&self) -> usize {
        NUM_FRI_FOLD_COLS
    }
}

impl<AB> Air<AB> for FriFoldChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        todo!()
    }
}
