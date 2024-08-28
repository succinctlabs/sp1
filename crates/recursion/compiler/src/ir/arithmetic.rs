// pub(crate) struct VarHandle<N> {}

use std::marker::PhantomData;

use super::{Ext, Felt, Var};

pub(crate) const EMPTY_OPS: EmptyOperations = EmptyOperations {};

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
}

#[derive(Debug)]
pub struct ExtHandle<F, EF> {
    ptr: *mut (),
    add_ext: fn(*mut (), Ext<F, EF>, Ext<F, EF>) -> Ext<F, EF>,
    sub_ext: fn(*mut (), Ext<F, EF>, Ext<F, EF>) -> Ext<F, EF>,
    mul_ext: fn(*mut (), Ext<F, EF>, Ext<F, EF>) -> Ext<F, EF>,
    add_const_ext: fn(*mut (), Ext<F, EF>, EF) -> Ext<F, EF>,
    add_const_base: fn(*mut (), Ext<F, EF>, F) -> Ext<F, EF>,
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

pub(crate) trait ExtOperations<F, EF> {
    fn add_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF>;
    fn sub_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF>;
    fn add_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF>;
    fn sub_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF>;
    fn sub_ext_from_base(ptr: *mut (), lhs: Felt<F>, rhs: Ext<F, EF>) -> Ext<F, EF>;
    fn mul_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF>;
    fn mul_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF>;
    fn add_const_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: EF) -> Ext<F, EF>;
    fn add_const_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: F) -> Ext<F, EF>;
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

impl<F> FeltOperations<F> for EmptyOperations {
    fn add_felt(_ptr: *mut (), _lhs: Felt<F>, _rhs: Felt<F>) -> Felt<F> {
        unimplemented!()
    }

    fn sub_felt(_ptr: *mut (), _lhs: Felt<F>, _rhs: Felt<F>) -> Felt<F> {
        unimplemented!()
    }

    fn mul_felt(_ptr: *mut (), _lhs: Felt<F>, _rhs: Felt<F>) -> Felt<F> {
        unimplemented!()
    }

    fn add_const_felt(ptr: *mut (), lhs: Felt<F>, rhs: F) -> Felt<F> {
        unimplemented!()
    }

    fn mul_const_felt(ptr: *mut (), lhs: Felt<F>, rhs: F) -> Felt<F> {
        unimplemented!()
    }

    fn sub_const_felt(ptr: *mut (), lhs: Felt<F>, rhs: F) -> Felt<F> {
        unimplemented!()
    }
}

impl<F, EF> ExtOperations<F, EF> for EmptyOperations {
    fn add_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF> {
        unimplemented!()
    }

    fn add_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF> {
        unimplemented!()
    }

    fn mul_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF> {
        unimplemented!()
    }

    fn mul_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF> {
        unimplemented!()
    }

    fn sub_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF> {
        unimplemented!()
    }

    fn sub_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF> {
        unimplemented!()
    }

    fn sub_ext_from_base(ptr: *mut (), lhs: Felt<F>, rhs: Ext<F, EF>) -> Ext<F, EF> {
        unimplemented!()
    }

    fn add_const_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: F) -> Ext<F, EF> {
        unimplemented!()
    }

    fn add_const_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: EF) -> Ext<F, EF> {
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

    pub fn felt_handle<F>() -> FeltHandle<F> {
        FeltHandle {
            ptr: std::ptr::null_mut(),
            add_felt: Self::add_felt,
            sub_felt: Self::sub_felt,
            mul_felt: Self::mul_felt,
            add_const: Self::add_const_felt,
        }
    }

    pub fn ext_handle<F, EF>() -> ExtHandle<F, EF> {
        ExtHandle {
            ptr: std::ptr::null_mut(),
            add_ext: Self::add_ext,
            sub_ext: Self::sub_ext,
            mul_ext: Self::mul_ext,
            add_const_base: Self::add_const_base,
            add_const_ext: Self::add_const_ext,
        }
    }
}
