use p3_air::BaseAir;

use crate::fri_fold::column::NUM_FRI_FOLD_COLS;
use crate::memory::MemoryRecord;

mod column;
mod trace;

/// A chip that implements the Fri Fold precompile.
#[derive(Default)]
pub struct FriFoldChip;

impl<F> BaseAir<F> for FriFoldChip {
    fn width(&self) -> usize {
        NUM_FRI_FOLD_COLS
    }
}

#[derive(Debug, Clone)]
pub struct FriFoldEvent<F> {
    pub m: MemoryRecord<F>,
    pub input_ptr: MemoryRecord<F>,

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
