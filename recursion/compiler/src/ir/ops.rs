use super::DslIR;
use core::marker::PhantomData;
use p3_field::AbstractField;

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

impl<C: Config> Variable<C> for Var<C::N> {
    fn uninit(builder: &mut Builder<C>) -> Self {
        let var = Var(builder.var_count, PhantomData);
        builder.var_count += 1;
        var
    }
}

impl<C: Config> Variable<C> for Felt<C::F> {
    fn uninit(builder: &mut Builder<C>) -> Self {
        let felt = Felt(builder.felt_count, PhantomData);
        builder.felt_count += 1;
        felt
    }
}

impl<C: Config> Variable<C> for Ext<C::F, C::EF> {
    fn uninit(builder: &mut Builder<C>) -> Self {
        let ext = Ext(builder.ext_count, PhantomData);
        builder.ext_count += 1;
        ext
    }
}

impl<C: Config> Expression<C> for Var<C::N> {
    type Value = Self;

    fn assign(&self, dst: Self::Value, builder: &mut Builder<C>) {
        builder
            .operations
            .push(DslIR::AddVI(dst, *self, C::N::zero()));
    }
}

impl<C: Config> Expression<C> for Felt<C::F> {
    type Value = Self;

    fn assign(&self, dst: Self::Value, builder: &mut Builder<C>) {
        builder
            .operations
            .push(DslIR::AddFI(dst, *self, C::F::zero()));
    }
}

impl<C: Config> Expression<C> for Ext<C::F, C::EF> {
    type Value = Self;

    fn assign(&self, dst: Self::Value, builder: &mut Builder<C>) {
        builder
            .operations
            .push(DslIR::AddEFI(dst, *self, C::F::zero()));
    }
}
