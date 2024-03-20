use super::{Builder, Config, MemVariable, Ptr, Usize, Var, Variable};
use itertools::Itertools;
use p3_field::AbstractField;

#[derive(Debug, Clone)]
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
                    slice[idx].clone()
                } else {
                    panic!("Cannot index into a fixed slice with a variable size")
                }
            }
            Array::Dyn(ptr, _) => {
                let var: V = self.uninit();
                self.load(var.clone(), *ptr + index * V::size_of());
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
                    self.assign(slice[idx].clone(), value);
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

impl<C: Config, T: MemVariable<C>> Variable<C> for Array<C, T> {
    type Expression = Self;

    fn uninit(_: &mut Builder<C>) -> Self {
        panic!("cannot allocate arrays on stack")
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        match (self, src.clone()) {
            (Array::Fixed(lhs), Array::Fixed(rhs)) => {
                for (l, r) in lhs.iter().zip_eq(rhs.iter()) {
                    builder.assign(l.clone(), r.clone());
                }
            }
            (Array::Dyn(_, lhs_len), Array::Dyn(_, rhs_len)) => {
                let lhs_len_var = builder.materialize(*lhs_len);
                let rhs_len_var = builder.materialize(rhs_len);
                builder.assert_eq::<Var<_>, _, _>(lhs_len_var, rhs_len_var);

                let start = Usize::Const(0);
                let end = *lhs_len;
                builder.range(start, end).for_each(|i, builder| {
                    let a = builder.get(self, i);
                    let b = builder.get(&src, i);
                    builder.assign(a, b);
                });
            }
            _ => panic!("cannot compare arrays of different types"),
        }
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs.clone(), rhs.clone()) {
            (Array::Fixed(lhs), Array::Fixed(rhs)) => {
                for (l, r) in lhs.iter().zip_eq(rhs.iter()) {
                    T::assert_eq(
                        T::Expression::from(l.clone()),
                        T::Expression::from(r.clone()),
                        builder,
                    );
                }
            }
            (Array::Dyn(_, lhs_len), Array::Dyn(_, rhs_len)) => {
                let lhs_len_var = builder.materialize(lhs_len);
                let rhs_len_var = builder.materialize(rhs_len);
                builder.assert_eq::<Var<_>, _, _>(lhs_len_var, rhs_len_var);

                let start = Usize::Const(0);
                let end = lhs_len;
                builder.range(start, end).for_each(|i, builder| {
                    let a = builder.get(&lhs, i);
                    let b = builder.get(&rhs, i);
                    T::assert_eq(T::Expression::from(a), T::Expression::from(b), builder);
                });
            }
            _ => panic!("cannot compare arrays of different types"),
        }
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs.clone(), rhs.clone()) {
            (Array::Fixed(lhs), Array::Fixed(rhs)) => {
                for (l, r) in lhs.iter().zip_eq(rhs.iter()) {
                    T::assert_ne(
                        T::Expression::from(l.clone()),
                        T::Expression::from(r.clone()),
                        builder,
                    );
                }
            }
            (Array::Dyn(_, lhs_len), Array::Dyn(_, rhs_len)) => {
                let lhs_len_var = builder.materialize(lhs_len);
                let rhs_len_var = builder.materialize(rhs_len);
                builder.assert_eq::<Var<_>, _, _>(lhs_len_var, rhs_len_var);

                let start = Usize::Const(0);
                let end = lhs_len;
                builder.range(start, end).for_each(|i, builder| {
                    let a = builder.get(&lhs, i);
                    let b = builder.get(&rhs, i);
                    T::assert_ne(T::Expression::from(a), T::Expression::from(b), builder);
                });
            }
            _ => panic!("cannot compare arrays of different types"),
        }
    }
}

impl<C: Config, T: MemVariable<C>> MemVariable<C> for Array<C, T> {
    fn size_of() -> usize {
        1
    }

    #[allow(clippy::needless_range_loop)]
    fn load(&self, src: Ptr<C::N>, builder: &mut Builder<C>) {
        match self {
            Array::Fixed(vec) => {
                for i in 0..vec.len() {
                    let addr = builder.eval(src + Usize::Const(i));
                    vec[i].clone().load(addr, builder);
                }
            }
            Array::Dyn(dst, _) => {
                builder.assign(*dst, src);
            }
        }
    }

    #[allow(clippy::needless_range_loop)]
    fn store(&self, dst: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        match self {
            Array::Fixed(vec) => {
                for i in 0..vec.len() {
                    let addr = builder.eval(dst + Usize::Const(i));
                    vec[i].clone().store(addr, builder);
                }
            }
            Array::Dyn(src, _) => {
                builder.assign(dst, *src);
            }
        }
    }
}
