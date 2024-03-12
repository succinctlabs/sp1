use super::Ptr;
use crate::old_ir::{Felt, Int};

pub type FieldVec<F> = Vector<Felt<F>>;

/// A vector with fixed capacity.
#[allow(dead_code)]
pub struct Vector<T> {
    ptr: Ptr<T>,
    len: Int,
    cap: usize,
}
