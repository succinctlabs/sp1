use super::{Builder, Config, MemVariable, Ptr, Usize, Var};
use p3_field::AbstractField;

#[derive(Clone)]
pub enum Array<C: Config, T> {
    Fixed(Vec<T>),
    Dyn(Ptr<C::N>, Usize<C::N>),
}

impl<C: Config, V: MemVariable<C>> Array<C, V> {
    pub fn len(&self) -> Usize<C::N> {
        match self {
            Self::Fixed(vec) => Usize::from(vec.len()),
            Self::Dyn(_, len) => *len,
        }
    }
}

impl<C: Config> Builder<C> {
    /// Initialize an array of fixed length `len`. The entries will be uninitialized.
    pub fn array<V: MemVariable<C>, I: Into<Usize<C::N>>>(&mut self, len: I) -> Array<C, V> {
        let len = len.into();
        match len {
            Usize::Const(len) => Array::Fixed(vec![self.uninit::<V>(); len]),
            Usize::Var(len) => {
                let len: Var<C::N> = self.eval(len * C::N::from_canonical_usize(V::size_of()));
                let len = Usize::Var(len);
                let ptr = self.alloc(len);
                Array::Dyn(ptr, len)
            }
        }
    }

    pub fn get<V: MemVariable<C>, I: Into<Usize<C::N>>>(
        &mut self,
        slice: &Array<C, V>,
        index: I,
    ) -> V {
        let index = index.into();

        match slice {
            Array::Fixed(slice) => {
                if let Usize::Const(idx) = index {
                    slice[idx]
                } else {
                    panic!("Cannot index into a fixed slice with a variable size")
                }
            }
            Array::Dyn(ptr, _) => {
                let var = self.uninit();
                self.load(var, *ptr + index * V::size_of());
                var
            }
        }
    }

    pub fn set<V: MemVariable<C>, I: Into<Usize<C::N>>, Expr: Into<V::Expression>>(
        &mut self,
        slice: &mut Array<C, V>,
        index: I,
        value: Expr,
    ) {
        let index = index.into();

        match slice {
            Array::Fixed(slice) => {
                if let Usize::Const(idx) = index {
                    self.assign(slice[idx], value);
                } else {
                    panic!("Cannot index into a fixed slice with a variable size")
                }
            }
            Array::Dyn(ptr, _) => {
                let value: V = self.eval(value);
                self.store(*ptr + index * V::size_of(), value);
            }
        }
    }
}
