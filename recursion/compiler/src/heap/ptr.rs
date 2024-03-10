use core::marker::PhantomData;

pub struct Ptr<T>(u32, PhantomData<T>);
