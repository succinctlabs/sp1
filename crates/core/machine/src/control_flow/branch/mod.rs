mod air;
mod columns;
mod trace;

pub use columns::*;
use p3_air::BaseAir;

#[derive(Default)]
pub struct BranchChip;

impl<F> BaseAir<F> for BranchChip {
    fn width(&self) -> usize {
        NUM_BRANCH_COLS
    }
}
