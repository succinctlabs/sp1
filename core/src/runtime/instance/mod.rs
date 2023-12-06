use anyhow::Result;

use crate::{program::ISA, segment::Segment};

pub mod simple;

/// A runtime instance.
///
/// A runtime instance is a collection of modules that have been instantiated together with a
/// shared store and a shared table.
pub trait Instance<S, IS: ISA> {
    type Segment: Segment;
    type Segments: IntoIterator<Item = Self::Segment>;

    fn max_segment_len(&self) -> usize;

    fn execute(
        &self,
        instruction: &IS::Instruction,
        store: &mut S,
        segment: &mut Self::Segment,
    ) -> Result<()>;

    fn run(&self, store: &mut S) -> Result<Self::Segments>;
}
