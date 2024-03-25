use super::{Builder, Config, Ptr};

pub trait Variable<C: Config>: Clone {
    type Expression: From<Self>;

    fn uninit(builder: &mut Builder<C>) -> Self;

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>);

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    );

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    );
}

pub trait MemVariable<C: Config>: Variable<C> {
    fn size_of() -> usize;
    fn load(&self, ptr: Ptr<C::N>, builder: &mut Builder<C>);
    fn store(&self, ptr: Ptr<C::N>, builder: &mut Builder<C>);
}
