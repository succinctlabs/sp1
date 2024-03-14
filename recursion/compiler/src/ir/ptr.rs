use super::{Builder, Config, DslIR, MemVariable, SymbolicVar, Usize, Var, Variable};

#[derive(Debug, Clone, Copy)]
pub struct Ptr<N> {
    address: Var<N>,
}

impl<C: Config> Builder<C> {
    pub(crate) fn alloc(&mut self, len: Usize<C::N>, size: usize) -> Ptr<C::N> {
        let ptr = Ptr::uninit(self);
        self.push(DslIR::Alloc(ptr, len, size));
        ptr
    }

    pub fn load<V: MemVariable<C>, I: Into<Usize<C::N>>>(
        &mut self,
        var: V,
        ptr: Ptr<C::N>,
        offset: I,
    ) {
        var.load(ptr, offset.into(), self);
    }

    pub fn store<V: MemVariable<C>, I: Into<Usize<C::N>>>(
        &mut self,
        ptr: Ptr<C::N>,
        offset: I,
        value: V,
    ) {
        value.store(ptr, offset.into(), self);
    }
}

impl<C: Config> Variable<C> for Ptr<C::N> {
    type Expression = SymbolicVar<C::N>;

    fn uninit(builder: &mut Builder<C>) -> Self {
        Ptr {
            address: Var::uninit(builder),
        }
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        self.address.assign(src, builder);
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        Var::assert_eq(lhs, rhs, builder);
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        Var::assert_ne(lhs, rhs, builder);
    }
}
