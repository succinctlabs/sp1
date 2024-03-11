use super::Ptr;
use crate::ir::{Felt, Int};

pub type FieldVec<F> = Vector<Felt<F>>;

/// A vector with fixed capacity.
pub struct Vector<T> {
    ptr: Ptr<T>,
    len: Int,
    cap: usize,
}
