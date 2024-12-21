mod air;
mod columns;
mod trace;

pub use columns::*;
use p3_air::BaseAir;

#[derive(Default)]
pub struct JumpChip;

impl<F> BaseAir<F> for JumpChip {
    fn width(&self) -> usize {
        NUM_JUMP_COLS
    }
}
