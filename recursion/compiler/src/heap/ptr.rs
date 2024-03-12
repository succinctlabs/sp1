use crate::ir::Int;
use core::marker::PhantomData;

/// A pointer to an absolute memory location.
#[allow(dead_code)]
pub struct Ptr<T>(Int, PhantomData<T>);
