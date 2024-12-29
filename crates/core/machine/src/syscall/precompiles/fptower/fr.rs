use std::marker::PhantomData;
pub struct FrOpChip<P> {
    _marker: PhantomData<P>,
}

impl<P> FrOpChip<P> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }
}