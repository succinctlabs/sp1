use std::marker::PhantomData;

use super::{Builder, Config, DslIR, MemVariable, Ptr, Usize, Variable};

pub enum Slice<C: Config, T> {
    Fixed(Vec<T>),
    Vec(Vector<C, T>),
}

pub struct Vector<C: Config, T> {
    ptr: Ptr<C::N>,
    len: Usize<C::N>,
    cap: Usize<C::N>,
    _marker: PhantomData<T>,
}

impl<C: Config> Builder<C> {
    pub fn vec<V: MemVariable<C>, I: Into<Usize<C::N>>>(&mut self, cap: I) -> Vector<C, V> {
        let cap = cap.into();
        Vector {
            ptr: self.alloc(cap, V::size_of()),
            len: Usize::from(0),
            cap,
            _marker: PhantomData,
        }
    }

    pub fn get<V: MemVariable<C>, I: Into<Usize<C::N>>>(
        &mut self,
        slice: &Slice<C, V>,
        index: I,
    ) -> V {
        let index = index.into();

        match slice {
            Slice::Fixed(slice) => {
                if let Usize::Const(idx) = index {
                    slice[idx]
                } else {
                    panic!("Cannot index into a fixed slice with a variable size")
                }
            }
            Slice::Vec(slice) => {
                let var = self.uninit();
                self.load(var, slice.ptr, index);
                var
            }
        }
    }
}
