use anyhow::Result;

use crate::segment::Segment;

/// A runtime instance.
///
/// A runtime instance is a collection of modules that have been instantiated together with a
/// shared store and a shared table.
pub trait Instance {
    type Store;

    type Segments: IntoIterator<Item = Segment>;

    fn run(&self, store: &mut Self::Store) -> Result<Self::Segments>;
}
