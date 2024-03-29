use itertools::Itertools;
use p3_field::AbstractField;

use super::{Builder, Config, Ext, FromConstant, MemVariable, Ptr, Usize, Var, Variable};
use super::{DslIR, Felt};

/// An array that is either of static or dynamic size.
///
/// If the target is a circuit-based system, then the arrays must be static. Other targets can
/// theoretically support both types of arrays..
#[derive(Debug, Clone)]
pub enum Array<C: Config, T> {
    Fixed(Vec<T>),
    Dyn(Ptr<C::N>, Usize<C::N>),
}

impl<C: Config, V: MemVariable<C>> Array<C, V> {
    /// Gets a fixed version of the array.
    pub fn vec(&self) -> Vec<V> {
        match self {
            Self::Fixed(vec) => vec.clone(),
            _ => panic!("array is dynamic, not fixed"),
        }
    }

    /// Gets the length of the array as a variable inside the DSL.
    pub fn len(&self) -> Usize<C::N> {
        match self {
            Self::Fixed(vec) => Usize::from(vec.len()),
            Self::Dyn(_, len) => *len,
        }
    }

    /// Gets the fixed length of the fixed-size array.
    pub fn static_len(&self) -> usize {
        match self {
            Self::Fixed(vec) => vec.len(),
            _ => panic!("cannot get the static length of a dynamic array"),
        }
    }

    /// Gets the n'th elment.
    pub fn static_get(&self, index: usize) -> V {
        match self {
            Self::Fixed(vec) => vec[index].clone(),
            _ => panic!("cannot get the n'th element of a dynamic array"),
        }
    }

    pub fn shift(&self, builder: &mut Builder<C>, shift: Var<C::N>) -> Array<C, V> {
        match self {
            Self::Fixed(_) => {
                todo!()
            }
            Self::Dyn(ptr, len) => {
                let new_address = builder.eval(ptr.address + shift);
                let new_ptr = Ptr::<C::N> {
                    address: new_address,
                };
                let len_var = len.materialize(builder);
                let new_length = builder.eval(len_var - shift);
                Array::Dyn(new_ptr, Usize::Var(new_length))
            }
        }
    }

    pub fn truncate(&self, builder: &mut Builder<C>, len: Usize<C::N>) {
        match self {
            Self::Fixed(_) => {
                todo!()
            }
            Self::Dyn(_, old_len) => {
                builder.assign(*old_len, len);
            }
        };
    }
}

impl<C: Config> Builder<C> {
    /// Initialize an array of fixed length `len`. The entries will be uninitialized.
    pub fn array<V: MemVariable<C>>(&mut self, len: impl Into<Usize<C::N>>) -> Array<C, V> {
        self.dyn_array(len)
    }

    pub fn vec<V: MemVariable<C>>(&mut self, v: Vec<V>) -> Array<C, V> {
        Array::Fixed(v)
    }

    pub fn select_v(&mut self, cond: Var<C::N>, a: Var<C::N>, b: Var<C::N>) -> Var<C::N> {
        let c = self.uninit();
        self.operations.push(DslIR::CircuitSelectV(cond, a, b, c));
        c
    }

    pub fn select_f(&mut self, cond: Var<C::N>, a: Felt<C::F>, b: Felt<C::F>) -> Felt<C::F> {
        let c = self.uninit();
        self.operations.push(DslIR::CircuitSelectF(cond, a, b, c));
        c
    }

    pub fn select_ef(
        &mut self,
        cond: Var<C::N>,
        a: Ext<C::F, C::EF>,
        b: Ext<C::F, C::EF>,
    ) -> Ext<C::F, C::EF> {
        let c = self.uninit();
        self.operations.push(DslIR::CircuitSelectEF(cond, a, b, c));
        c
    }

    pub fn dyn_array<V: MemVariable<C>>(&mut self, len: impl Into<Usize<C::N>>) -> Array<C, V> {
        let len = match len.into() {
            Usize::Const(len) => self.eval(C::N::from_canonical_usize(len)),
            Usize::Var(len) => len,
        };
        let size: Var<C::N> = self.eval(len * C::N::from_canonical_usize(V::size_of()));
        let size = Usize::Var(size);
        let ptr = self.alloc(size);
        Array::Dyn(ptr, Usize::Var(len))
    }

    pub fn array_to_dyn<V: MemVariable<C>>(&mut self, array: Array<C, V>) -> Array<C, V> {
        match array {
            Array::Fixed(v) => {
                let mut dyn_array = self.dyn_array(v.len());

                for (i, value) in v.into_iter().enumerate() {
                    self.set(&mut dyn_array, i, value);
                }
                dyn_array
            }
            Array::Dyn(ptr, len) => Array::Dyn(ptr, len),
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
            Array::Fixed(_) => {
                todo!()
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

    fn uninit(builder: &mut Builder<C>) -> Self {
        Array::Dyn(builder.uninit(), builder.uninit())
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        match (self, src.clone()) {
            (Array::Dyn(lhs_ptr, lhs_len), Array::Dyn(rhs_ptr, rhs_len)) => {
                builder.assign(*lhs_ptr, rhs_ptr);
                builder.assign(*lhs_len, rhs_len);
            }
            _ => unreachable!(),
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
        2
    }

    fn load(&self, src: Ptr<C::N>, builder: &mut Builder<C>) {
        match self {
            Array::Dyn(dst, Usize::Var(len)) => {
                let mut offset = 0;
                let address = builder.eval(src + Usize::Const(offset));
                dst.load(address, builder);
                offset += <Ptr<C::N> as MemVariable<C>>::size_of();
                let address = builder.eval(src + Usize::Const(offset));
                len.load(address, builder);
            }
            _ => unreachable!(),
        }
    }

    fn store(&self, dst: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        match self {
            Array::Dyn(src, Usize::Var(len)) => {
                let mut offset = 0;
                let address = builder.eval(dst + Usize::Const(offset));
                src.store(address, builder);
                offset += <Ptr<C::N> as MemVariable<C>>::size_of();
                let address = builder.eval(dst + Usize::Const(offset));
                len.store(address, builder);
            }
            _ => unreachable!(),
        }
    }
}

impl<C: Config, V: FromConstant<C> + MemVariable<C>> FromConstant<C> for Array<C, V> {
    type Constant = Vec<V::Constant>;

    fn eval_const(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        let mut array = builder.dyn_array(value.len());
        // Assign each element.
        for (i, val) in value.into_iter().enumerate() {
            let val = V::eval_const(val, builder);
            builder.set(&mut array, i, val);
        }
        array
    }
}
