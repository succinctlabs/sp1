use crate::ir::Builder;
use crate::ir::SizedVariable;
use crate::ir::Variable;
use core::marker::PhantomData;

pub struct Ptr<T>(u32, PhantomData<T>);

// impl<B: Builder, T: SizedVariable<B>> Variable<B> for Ptr<T> {
//     fn uninit(builder: &mut B) -> Self {
//         let address = builder.alloc(T::size_of());
//         Ptr(address, PhantomData)
//     }
// }
