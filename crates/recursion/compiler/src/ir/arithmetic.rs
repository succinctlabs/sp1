// pub(crate) struct VarHandle<N> {}

use std::marker::PhantomData;

use super::{Ext, Felt, Var};

#[derive(Debug)]
pub struct VarHandle<N> {
    ptr: *mut (),
    add_var: fn(*mut (), Var<N>, Var<N>) -> Var<N>,
    sub_var: fn(*mut (), Var<N>, Var<N>) -> Var<N>,
    mul_var: fn(*mut (), Var<N>, Var<N>) -> Var<N>,
    add_const: fn(*mut (), Var<N>, N) -> Var<N>,
    sub_var_const: fn(*mut (), Var<N>, N) -> Var<N>,
    sub_const_var: fn(*mut (), N, Var<N>) -> Var<N>,
    mul_const: fn(*mut (), Var<N>, N) -> Var<N>,
}

#[derive(Debug)]
pub struct FeltHandle<F> {
    ptr: *mut (),
    add_felt: fn(*mut (), Felt<F>, Felt<F>) -> Felt<F>,
    sub_felt: fn(*mut (), Felt<F>, Felt<F>) -> Felt<F>,
    mul_felt: fn(*mut (), Felt<F>, Felt<F>) -> Felt<F>,
    add_const: fn(*mut (), Felt<F>, F) -> Felt<F>,
    sub_const: fn(*mut (), Felt<F>, F) -> Felt<F>,
    mul_const: fn(*mut (), Felt<F>, F) -> Felt<F>,
}

pub struct ExtHandle<F, EF> {
    ptr: *mut (),
    add_ext: fn(*mut (), Ext<F, EF>, Ext<F, EF>) -> Ext<F, EF>,
    sub_ext: fn(*mut (), Ext<F, EF>, Ext<F, EF>) -> Ext<F, EF>,
    mul_ext: fn(*mut (), Ext<F, EF>, Ext<F, EF>) -> Ext<F, EF>,
    add_const: fn(*mut (), Ext<F, EF>, F) -> Ext<F, EF>,
    sub_const: fn(*mut (), Ext<F, EF>, F) -> Ext<F, EF>,
    mul_const: fn(*mut (), Ext<F, EF>, F) -> Ext<F, EF>,
    _marker: PhantomData<(F, EF)>,
}

pub(crate) trait VarOperations<N> {
    fn add_var(ptr: *mut (), lhs: Var<N>, rhs: Var<N>) -> Var<N>;

    fn sub_var(ptr: *mut (), lhs: Var<N>, rhs: Var<N>) -> Var<N>;

    fn mul_var(ptr: *mut (), lhs: Var<N>, rhs: Var<N>) -> Var<N>;

    fn add_const_var(ptr: *mut (), lhs: Var<N>, rhs: N) -> Var<N>;

    fn sub_var_const(ptr: *mut (), lhs: Var<N>, rhs: N) -> Var<N>;

    fn sub_const_var(ptr: *mut (), lhs: N, rhs: Var<N>) -> Var<N>;

    fn mul_const_var(ptr: *mut (), lhs: Var<N>, rhs: N) -> Var<N>;
}

pub(crate) trait FeltOperations<F> {
    fn add_felt(ptr: *mut (), lhs: Felt<F>, rhs: Felt<F>) -> Felt<F>;
    fn sub_felt(ptr: *mut (), lhs: Felt<F>, rhs: Felt<F>) -> Felt<F>;
    fn mul_felt(ptr: *mut (), lhs: Felt<F>, rhs: Felt<F>) -> Felt<F>;
    fn add_const_felt(ptr: *mut (), lhs: Felt<F>, rhs: F) -> Felt<F>;
    fn sub_const_felt(ptr: *mut (), lhs: Felt<F>, rhs: F) -> Felt<F>;
    fn mul_const_felt(ptr: *mut (), lhs: Felt<F>, rhs: F) -> Felt<F>;
}

pub struct EmptyOperations;

impl<N> VarOperations<N> for EmptyOperations {
    fn add_var(_ptr: *mut (), _lhs: Var<N>, _rhs: Var<N>) -> Var<N> {
        unimplemented!()
    }

    fn sub_var(_ptr: *mut (), _lhs: Var<N>, _rhs: Var<N>) -> Var<N> {
        unimplemented!()
    }

    fn mul_var(_ptr: *mut (), _lhs: Var<N>, _rhs: Var<N>) -> Var<N> {
        unimplemented!()
    }

    fn add_const_var(_ptr: *mut (), _lhs: Var<N>, _rhs: N) -> Var<N> {
        unimplemented!()
    }

    fn sub_var_const(_ptr: *mut (), _lhs: Var<N>, _rhs: N) -> Var<N> {
        unimplemented!()
    }

    fn sub_const_var(_ptr: *mut (), _lhs: N, _rhs: Var<N>) -> Var<N> {
        unimplemented!()
    }

    fn mul_const_var(_ptr: *mut (), _lhs: Var<N>, _rhs: N) -> Var<N> {
        unimplemented!()
    }
}

impl EmptyOperations {
    pub fn var_handle<N>() -> VarHandle<N> {
        VarHandle {
            ptr: std::ptr::null_mut(),
            add_var: Self::add_var,
            sub_var: Self::sub_var,
            mul_var: Self::mul_var,
            add_const: Self::add_const_var,
            sub_var_const: Self::sub_var_const,
            sub_const_var: Self::sub_const_var,
            mul_const: Self::mul_const_var,
        }
    }
}
