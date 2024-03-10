use super::Ptr;
use crate::ir::Felt;

pub type FieldVec<F> = Vector<Felt<F>>;

/// A vector with fixed capacity.
pub struct Vector<T> {
    ptr: Ptr<T>,
    cap: usize,
}
