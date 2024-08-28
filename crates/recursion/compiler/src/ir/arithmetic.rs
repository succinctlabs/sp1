use std::cell::UnsafeCell;

use p3_field::AbstractExtensionField;

use crate::ir::DslIr;

use super::{Config, Ext, Felt, InnerBuilder, Var};

pub(crate) const EMPTY_OPS: EmptyOperations = EmptyOperations;

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

    fn var_handle(&self) -> VarHandle<N> {
        VarHandle {
            ptr: self as *const Self as *mut (),
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

pub(crate) trait FeltOperations<F> {
    fn add_felt(ptr: *mut (), lhs: Felt<F>, rhs: Felt<F>) -> Felt<F>;
    fn sub_felt(ptr: *mut (), lhs: Felt<F>, rhs: Felt<F>) -> Felt<F>;
    fn mul_felt(ptr: *mut (), lhs: Felt<F>, rhs: Felt<F>) -> Felt<F>;
    fn add_const_felt(ptr: *mut (), lhs: Felt<F>, rhs: F) -> Felt<F>;
    fn sub_const_felt(ptr: *mut (), lhs: Felt<F>, rhs: F) -> Felt<F>;
    fn mul_const_felt(ptr: *mut (), lhs: Felt<F>, rhs: F) -> Felt<F>;

    fn felt_handle(&self) -> FeltHandle<F> {
        FeltHandle {
            ptr: self as *const Self as *mut (),
            add_felt: Self::add_felt,
            sub_felt: Self::sub_felt,
            mul_felt: Self::mul_felt,
            add_const: Self::add_const_felt,
        }
    }
}

pub(crate) trait ExtOperations<F, EF> {
    fn add_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF>;
    fn sub_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF>;
    fn add_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF>;
    fn sub_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF>;
    fn mul_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF>;
    fn mul_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF>;
    fn add_const_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: EF) -> Ext<F, EF>;
    fn add_const_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: F) -> Ext<F, EF>;

    fn ext_handle(&self) -> ExtHandle<F, EF> {
        ExtHandle {
            ptr: self as *const Self as *mut (),
            add_ext: Self::add_ext,
            sub_ext: Self::sub_ext,
            mul_ext: Self::mul_ext,
            add_const_base: Self::add_const_base,
            add_const_ext: Self::add_const_ext,
        }
    }
}

pub struct EmptyOperations;

impl<C: Config> VarOperations<C::N> for UnsafeCell<InnerBuilder<C>> {
    fn add_var(ptr: *mut (), lhs: Var<C::N>, rhs: Var<C::N>) -> Var<C::N> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Var::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::AddV(res, lhs, rhs));

        res
    }

    fn sub_var(ptr: *mut (), lhs: Var<C::N>, rhs: Var<C::N>) -> Var<C::N> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Var::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::SubV(res, lhs, rhs));

        res
    }

    fn mul_var(ptr: *mut (), lhs: Var<C::N>, rhs: Var<C::N>) -> Var<C::N> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Var::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::MulV(res, lhs, rhs));

        res
    }

    fn add_const_var(ptr: *mut (), lhs: Var<C::N>, rhs: C::N) -> Var<C::N> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Var::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::AddVI(res, lhs, rhs));

        res
    }

    fn mul_const_var(ptr: *mut (), lhs: Var<C::N>, rhs: C::N) -> Var<C::N> {
        unimplemented!()
    }

    fn sub_const_var(ptr: *mut (), lhs: C::N, rhs: Var<C::N>) -> Var<C::N> {
        unimplemented!()
    }

    fn sub_var_const(ptr: *mut (), lhs: Var<C::N>, rhs: C::N) -> Var<C::N> {
        unimplemented!()
    }
}

impl<C: Config> FeltOperations<C::F> for UnsafeCell<InnerBuilder<C>> {
    fn add_felt(ptr: *mut (), lhs: Felt<C::F>, rhs: Felt<C::F>) -> Felt<C::F> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::AddF(res, lhs, rhs));

        res
    }

    fn sub_felt(ptr: *mut (), lhs: Felt<C::F>, rhs: Felt<C::F>) -> Felt<C::F> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::SubF(res, lhs, rhs));

        res
    }

    fn mul_felt(ptr: *mut (), lhs: Felt<C::F>, rhs: Felt<C::F>) -> Felt<C::F> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::MulF(res, lhs, rhs));

        res
    }

    fn add_const_felt(ptr: *mut (), lhs: Felt<C::F>, rhs: C::F) -> Felt<C::F> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::AddFI(res, lhs, rhs));

        res
    }

    fn sub_const_felt(ptr: *mut (), lhs: Felt<C::F>, rhs: C::F) -> Felt<C::F> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::SubFI(res, lhs, rhs));

        res
    }

    fn mul_const_felt(ptr: *mut (), lhs: Felt<C::F>, rhs: C::F) -> Felt<C::F> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::MulFI(res, lhs, rhs));

        res
    }
}

impl<C: Config> ExtOperations<C::F, C::EF> for UnsafeCell<InnerBuilder<C>> {
    fn add_ext(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: Ext<C::F, C::EF>) -> Ext<C::F, C::EF> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::AddE(res, lhs, rhs));

        res
    }

    fn sub_ext(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: Ext<C::F, C::EF>) -> Ext<C::F, C::EF> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::SubE(res, lhs, rhs));

        res
    }

    fn mul_ext(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: Ext<C::F, C::EF>) -> Ext<C::F, C::EF> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::MulE(res, lhs, rhs));

        res
    }

    fn add_base(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: Felt<C::F>) -> Ext<C::F, C::EF> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::AddEF(res, lhs, rhs));

        res
    }

    fn mul_base(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: Felt<C::F>) -> Ext<C::F, C::EF> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::MulEF(res, lhs, rhs));

        res
    }

    fn sub_base(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: Felt<C::F>) -> Ext<C::F, C::EF> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::SubEF(res, lhs, rhs));

        res
    }

    fn add_const_base(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: C::F) -> Ext<C::F, C::EF> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::AddEFI(res, lhs, rhs));

        res
    }

    fn add_const_ext(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: C::EF) -> Ext<C::F, C::EF> {
        let inner: &mut Self = unsafe { &mut *(ptr as *mut Self) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::AddEI(res, lhs, rhs));

        res
    }
}

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

    fn add_const_felt(ptr: *mut (), _lhs: Felt<F>, _rhs: F) -> Felt<F> {
        unimplemented!()
    }

    fn mul_const_felt(ptr: *mut (), _lhs: Felt<F>, _rhs: F) -> Felt<F> {
        unimplemented!()
    }

    fn sub_const_felt(ptr: *mut (), _lhs: Felt<F>, _rhs: F) -> Felt<F> {
        unimplemented!()
    }
}

impl<F, EF> ExtOperations<F, EF> for EmptyOperations {
    fn add_ext(_ptr: *mut (), _lhs: Ext<F, EF>, _rhs: Ext<F, EF>) -> Ext<F, EF> {
        unimplemented!()
    }

    fn add_base(_ptr: *mut (), _lhs: Ext<F, EF>, _rhs: Felt<F>) -> Ext<F, EF> {
        unimplemented!()
    }

    fn mul_base(_ptr: *mut (), _lhs: Ext<F, EF>, _rhs: Felt<F>) -> Ext<F, EF> {
        unimplemented!()
    }

    fn mul_ext(_ptr: *mut (), _lhs: Ext<F, EF>, _rhs: Ext<F, EF>) -> Ext<F, EF> {
        unimplemented!()
    }

    fn sub_ext(_ptr: *mut (), _lhs: Ext<F, EF>, _rhs: Ext<F, EF>) -> Ext<F, EF> {
        unimplemented!()
    }

    fn sub_base(_ptr: *mut (), _lhs: Ext<F, EF>, _rhs: Felt<F>) -> Ext<F, EF> {
        unimplemented!()
    }

    fn add_const_base(_ptr: *mut (), _lhs: Ext<F, EF>, _rhs: F) -> Ext<F, EF> {
        unimplemented!()
    }

    fn add_const_ext(_ptr: *mut (), _lhs: Ext<F, EF>, _rhs: EF) -> Ext<F, EF> {
        unimplemented!()
    }
}
