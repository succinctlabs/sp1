use core::marker::PhantomData;

#[allow(dead_code)]
pub struct Ptr<T>(u32, PhantomData<T>);
