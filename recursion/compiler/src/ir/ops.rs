use core::marker::PhantomData;

use super::{Builder, Config, Ext, Felt, Var};
pub trait Variable<C: Config> {
    fn uninit(builder: &mut Builder<C>) -> Self;
}

pub trait Expression<C: Config> {
    type Value;

    fn assign(&self, dst: Self::Value, builder: &mut Builder<C>);
}

pub trait Equal<C: Config, Rhs = Self> {
    fn assert_equal(&self, rhs: &Rhs, builder: &mut Builder<C>);
}

impl<C: Config> Variable<C> for Var<C> {
    fn uninit(builder: &mut Builder<C>) -> Self {
        let var = Var(builder.var_count, PhantomData);
        builder.var_count += 1;
        var
    }
}

impl<C: Config> Variable<C> for Felt<C> {
    fn uninit(builder: &mut Builder<C>) -> Self {
        let felt = Felt(builder.felt_count, PhantomData);
        builder.felt_count += 1;
        felt
    }
}

impl<C: Config> Variable<C> for Ext<C> {
    fn uninit(builder: &mut Builder<C>) -> Self {
        let ext = Ext(builder.ext_count, PhantomData);
        builder.ext_count += 1;
        ext
    }
}
