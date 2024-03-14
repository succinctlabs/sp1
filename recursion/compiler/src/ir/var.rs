use super::{Builder, Config, Ptr, Usize};
pub trait Variable<C: Config>: Copy {
    type Expression;

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
    fn load(&self, ptr: Ptr<C::N>, offset: Usize<C::N>, builder: &mut Builder<C>);
    fn store(&self, ptr: Ptr<C::N>, offset: Usize<C::N>, builder: &mut Builder<C>);
}
