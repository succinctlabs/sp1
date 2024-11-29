use columns::NUM_MEMORY_INSTRUCTIONS_COLUMNS;
use p3_air::BaseAir;

pub mod air;
pub mod columns;
pub mod trace;

#[derive(Default)]
pub struct MemoryInstructionsChip;

impl<F> BaseAir<F> for MemoryInstructionsChip {
    fn width(&self) -> usize {
        NUM_MEMORY_INSTRUCTIONS_COLUMNS
    }
}
