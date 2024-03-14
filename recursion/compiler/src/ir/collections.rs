use std::marker::PhantomData;

use super::{Builder, Config, MemVariable, Ptr, Usize};

pub enum Slice<C: Config, T> {
    Fixed(Vec<T>),
    Vec(Vector<C, T>),
}

#[allow(dead_code)]
pub struct Vector<C: Config, T> {
    ptr: Ptr<C::N>,
    len: Usize<C::N>,
    cap: Usize<C::N>,
    _marker: PhantomData<T>,
}

impl<C: Config, V: MemVariable<C>> Vector<C, V> {
    pub fn len(&self) -> Usize<C::N> {
        self.len
    }
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

    pub fn set<V: MemVariable<C>, I: Into<Usize<C::N>>>(
        &mut self,
        slice: &mut Slice<C, V>,
        index: I,
        value: V,
    ) {
        let index = index.into();

        match slice {
            Slice::Fixed(slice) => {
                if let Usize::Const(idx) = index {
                    slice[idx] = value;
                } else {
                    panic!("Cannot index into a fixed slice with a variable size")
                }
            }
            Slice::Vec(slice) => {
                self.store(slice.ptr, index, value);
            }
        }
    }
}
