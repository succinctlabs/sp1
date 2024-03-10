use core::marker::PhantomData;

/// A pointer to an absolute memory location.
pub struct Ptr<T>(u32, PhantomData<T>);
