use std::{cell::UnsafeCell, mem::ManuallyDrop};

use p3_field::{AbstractExtensionField, AbstractField, Field};

use crate::ir::DslIr;

use super::{Config, Ext, Felt, InnerBuilder, Var};

#[derive(Debug)]
pub struct VarHandle<N> {
    ptr: *mut (),

    add_var: fn(*mut (), Var<N>, Var<N>) -> Var<N>,
    add_var_const: fn(*mut (), Var<N>, N) -> Var<N>,

    sub_var: fn(*mut (), Var<N>, Var<N>) -> Var<N>,
    sub_var_const: fn(*mut (), Var<N>, N) -> Var<N>,
    sub_const_var: fn(*mut (), N, Var<N>) -> Var<N>,

    neg_var: fn(ptr: *mut (), lhs: Var<N>) -> Var<N>,

    mul_var: fn(*mut (), Var<N>, Var<N>) -> Var<N>,
    mul_var_const: fn(*mut (), Var<N>, N) -> Var<N>,
}

#[derive(Debug)]
pub struct FeltHandle<F> {
    ptr: *mut (),

    pub ext_handle_ptr: *mut (),

    add_felt: fn(*mut (), Felt<F>, Felt<F>) -> Felt<F>,
    add_const_felt: fn(*mut (), Felt<F>, F) -> Felt<F>,

    sub_felt: fn(*mut (), Felt<F>, Felt<F>) -> Felt<F>,
    sub_const_felt: fn(*mut (), F, Felt<F>) -> Felt<F>,
    sub_felt_const: fn(*mut (), Felt<F>, F) -> Felt<F>,

    neg_felt: fn(ptr: *mut (), lhs: Felt<F>) -> Felt<F>,

    mul_felt: fn(*mut (), Felt<F>, Felt<F>) -> Felt<F>,
    mul_felt_const: fn(ptr: *mut (), lhs: Felt<F>, rhs: F) -> Felt<F>,

    div_felt: fn(*mut (), Felt<F>, Felt<F>) -> Felt<F>,
    div_felt_const: fn(*mut (), Felt<F>, F) -> Felt<F>,
    div_const_felt: fn(*mut (), F, Felt<F>) -> Felt<F>,
}

#[derive(Debug)]
pub struct ExtHandle<F, EF> {
    ptr: *mut (),

    add_ext: fn(*mut (), Ext<F, EF>, Ext<F, EF>) -> Ext<F, EF>,
    add_const_ext: fn(*mut (), Ext<F, EF>, EF) -> Ext<F, EF>,
    add_ext_base: fn(*mut (), Ext<F, EF>, Felt<F>) -> Ext<F, EF>,
    add_const_base: fn(*mut (), Ext<F, EF>, F) -> Ext<F, EF>,
    add_felt_const_ext: fn(*mut (), Felt<F>, EF, *mut Self) -> Ext<F, EF>,

    sub_ext: fn(*mut (), Ext<F, EF>, Ext<F, EF>) -> Ext<F, EF>,
    sub_ext_base: fn(*mut (), Ext<F, EF>, Felt<F>) -> Ext<F, EF>,
    sub_base_ext: fn(*mut (), Felt<F>, Ext<F, EF>) -> Ext<F, EF>,
    sub_felt_const_ext: fn(*mut (), Felt<F>, EF, *mut Self) -> Ext<F, EF>,
    sub_const_ext: fn(*mut (), Ext<F, EF>, EF) -> Ext<F, EF>,
    sub_ext_const: fn(*mut (), EF, Ext<F, EF>) -> Ext<F, EF>,

    neg_ext: fn(ptr: *mut (), lhs: Ext<F, EF>) -> Ext<F, EF>,

    div_ext: fn(*mut (), Ext<F, EF>, Ext<F, EF>) -> Ext<F, EF>,
    div_const_ext: fn(*mut (), Ext<F, EF>, EF) -> Ext<F, EF>,
    div_ext_base: fn(*mut (), Ext<F, EF>, Felt<F>) -> Ext<F, EF>,
    div_base_ext: fn(*mut (), Felt<F>, Ext<F, EF>) -> Ext<F, EF>,
    div_const_base: fn(*mut (), Ext<F, EF>, F) -> Ext<F, EF>,
    div_ext_const: fn(*mut (), EF, Ext<F, EF>) -> Ext<F, EF>,
    div_felt_const_ext: fn(*mut (), Felt<F>, EF, *mut Self) -> Ext<F, EF>,

    mul_ext: fn(*mut (), Ext<F, EF>, Ext<F, EF>) -> Ext<F, EF>,
    mul_const_ext: fn(*mut (), Ext<F, EF>, EF) -> Ext<F, EF>,
    mul_ext_base: fn(*mut (), Ext<F, EF>, Felt<F>) -> Ext<F, EF>,
    mul_felt_const_ext: fn(*mut (), Felt<F>, EF, *mut Self) -> Ext<F, EF>,
}

pub(crate) trait VarOperations<N> {
    fn add_var(ptr: *mut (), lhs: Var<N>, rhs: Var<N>) -> Var<N>;
    fn add_const_var(ptr: *mut (), lhs: Var<N>, rhs: N) -> Var<N>;

    fn sub_var(ptr: *mut (), lhs: Var<N>, rhs: Var<N>) -> Var<N>;
    fn sub_var_const(ptr: *mut (), lhs: Var<N>, rhs: N) -> Var<N>;
    fn sub_const_var(ptr: *mut (), lhs: N, rhs: Var<N>) -> Var<N>;

    fn neg_var(ptr: *mut (), lhs: Var<N>) -> Var<N>;

    fn mul_var(ptr: *mut (), lhs: Var<N>, rhs: Var<N>) -> Var<N>;
    fn mul_const_var(ptr: *mut (), lhs: Var<N>, rhs: N) -> Var<N>;

    fn var_handle(element: &mut Box<Self>) -> VarHandle<N> {
        VarHandle {
            ptr: element.as_mut() as *mut Self as *mut (),
            add_var: Self::add_var,
            sub_var: Self::sub_var,
            mul_var: Self::mul_var,
            neg_var: Self::neg_var,
            add_var_const: Self::add_const_var,
            sub_var_const: Self::sub_var_const,
            sub_const_var: Self::sub_const_var,
            mul_var_const: Self::mul_const_var,
        }
    }
}

pub(crate) trait FeltOperations<F> {
    fn add_felt(ptr: *mut (), lhs: Felt<F>, rhs: Felt<F>) -> Felt<F>;
    fn sub_felt(ptr: *mut (), lhs: Felt<F>, rhs: Felt<F>) -> Felt<F>;
    fn mul_felt(ptr: *mut (), lhs: Felt<F>, rhs: Felt<F>) -> Felt<F>;
    fn add_felt_const(ptr: *mut (), lhs: Felt<F>, rhs: F) -> Felt<F>;
    fn sub_felt_const(ptr: *mut (), lhs: Felt<F>, rhs: F) -> Felt<F>;
    fn mul_const_felt(ptr: *mut (), lhs: Felt<F>, rhs: F) -> Felt<F>;
    fn sub_const_felt(ptr: *mut (), lhs: F, rhs: Felt<F>) -> Felt<F>;
    fn div_felt(ptr: *mut (), lhs: Felt<F>, rhs: Felt<F>) -> Felt<F>;
    fn div_felt_const(ptr: *mut (), lhs: Felt<F>, rhs: F) -> Felt<F>;
    fn div_const_felt(ptr: *mut (), lhs: F, rhs: Felt<F>) -> Felt<F>;
    fn neg_felt(ptr: *mut (), lhs: Felt<F>) -> Felt<F>;

    fn felt_handle(element: &mut Box<Self>, ext_handle_ptr: *mut ()) -> FeltHandle<F> {
        FeltHandle {
            ptr: element.as_mut() as *mut Self as *mut (),
            ext_handle_ptr,
            add_felt: Self::add_felt,
            sub_felt: Self::sub_felt,
            mul_felt: Self::mul_felt,
            add_const_felt: Self::add_felt_const,
            mul_felt_const: Self::mul_const_felt,
            sub_felt_const: Self::sub_felt_const,
            sub_const_felt: Self::sub_const_felt,
            div_felt: Self::div_felt,
            div_felt_const: Self::div_felt_const,
            div_const_felt: Self::div_const_felt,
            neg_felt: Self::neg_felt,
        }
    }
}

pub(crate) trait ExtOperations<F, EF> {
    fn add_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF>;
    fn add_felt_const_ext(
        ptr: *mut (),
        lhs: Felt<F>,
        rhs: EF,
        handle: *mut ExtHandle<F, EF>,
    ) -> Ext<F, EF>;
    fn add_ext_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF>;
    fn add_const_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: EF) -> Ext<F, EF>;
    fn add_const_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: F) -> Ext<F, EF>;

    fn neg_ext(ptr: *mut (), lhs: Ext<F, EF>) -> Ext<F, EF>;

    fn sub_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF>;
    fn sub_ext_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF>;
    fn sub_base_ext(ptr: *mut (), lhs: Felt<F>, rhs: Ext<F, EF>) -> Ext<F, EF>;
    fn sub_ext_const(ptr: *mut (), lhs: EF, rhs: Ext<F, EF>) -> Ext<F, EF>;
    fn sub_const_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: EF) -> Ext<F, EF>;
    fn sub_felt_const_ext(
        ptr: *mut (),
        lhs: Felt<F>,
        rhs: EF,
        handle: *mut ExtHandle<F, EF>,
    ) -> Ext<F, EF>;

    fn div_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF>;
    fn div_ext_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF>;
    fn div_base_ext(ptr: *mut (), lhs: Felt<F>, rhs: Ext<F, EF>) -> Ext<F, EF>;
    fn div_const_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: EF) -> Ext<F, EF>;
    fn div_ext_const(ptr: *mut (), lhs: EF, rhs: Ext<F, EF>) -> Ext<F, EF>;
    fn div_const_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: F) -> Ext<F, EF>;
    fn div_felt_const_ext(
        ptr: *mut (),
        lhs: Felt<F>,
        rhs: EF,
        handle: *mut ExtHandle<F, EF>,
    ) -> Ext<F, EF>;

    fn mul_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF>;
    fn mul_const_ext(ptr: *mut (), lhs: Ext<F, EF>, rhs: EF) -> Ext<F, EF>;
    fn mul_felt_const_ext(
        ptr: *mut (),
        lhs: Felt<F>,
        rhs: EF,
        handle: *mut ExtHandle<F, EF>,
    ) -> Ext<F, EF>;
    fn mul_ext_base(ptr: *mut (), lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF>;

    fn ext_handle(element: &mut Box<Self>) -> ExtHandle<F, EF> {
        ExtHandle {
            ptr: element.as_mut() as *mut Self as *mut (),
            add_ext: Self::add_ext,
            add_ext_base: Self::add_ext_base,
            add_felt_const_ext: Self::add_felt_const_ext,
            sub_ext: Self::sub_ext,
            sub_base_ext: Self::sub_base_ext,
            add_const_base: Self::add_const_base,
            add_const_ext: Self::add_const_ext,
            neg_ext: Self::neg_ext,
            sub_ext_base: Self::sub_ext_base,
            sub_felt_const_ext: Self::sub_felt_const_ext,
            sub_const_ext: Self::sub_const_ext,
            div_ext: Self::div_ext,
            div_const_ext: Self::div_const_ext,
            div_felt_const_ext: Self::div_felt_const_ext,
            div_ext_base: Self::div_ext_base,
            sub_ext_const: Self::sub_ext_const,
            div_base_ext: Self::div_base_ext,
            div_const_base: Self::div_const_base,
            mul_ext: Self::mul_ext,
            mul_const_ext: Self::mul_const_ext,
            mul_ext_base: Self::mul_ext_base,
            mul_felt_const_ext: Self::mul_felt_const_ext,
            div_ext_const: Self::div_ext_const,
        }
    }
}

impl<C: Config> VarOperations<C::N> for UnsafeCell<InnerBuilder<C>> {
    fn add_var(ptr: *mut (), lhs: Var<C::N>, rhs: Var<C::N>) -> Var<C::N> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Var::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::AddV(res, lhs, rhs));

        res
    }

    fn sub_var(ptr: *mut (), lhs: Var<C::N>, rhs: Var<C::N>) -> Var<C::N> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Var::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::SubV(res, lhs, rhs));

        res
    }

    fn mul_var(ptr: *mut (), lhs: Var<C::N>, rhs: Var<C::N>) -> Var<C::N> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Var::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::MulV(res, lhs, rhs));

        res
    }

    fn add_const_var(ptr: *mut (), lhs: Var<C::N>, rhs: C::N) -> Var<C::N> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Var::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::AddVI(res, lhs, rhs));

        res
    }

    fn mul_const_var(ptr: *mut (), lhs: Var<C::N>, rhs: C::N) -> Var<C::N> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Var::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::MulVI(res, lhs, rhs));

        res
    }

    fn sub_const_var(ptr: *mut (), lhs: C::N, rhs: Var<C::N>) -> Var<C::N> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Var::new(idx, rhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::SubVIN(res, lhs, rhs));

        res
    }

    fn sub_var_const(ptr: *mut (), lhs: Var<C::N>, rhs: C::N) -> Var<C::N> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Var::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::SubVI(res, lhs, rhs));

        res
    }

    fn neg_var(ptr: *mut (), lhs: Var<C::N>) -> Var<C::N> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Var::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::NegV(res, lhs));

        res
    }
}

impl<C: Config> FeltOperations<C::F> for UnsafeCell<InnerBuilder<C>> {
    fn add_felt(ptr: *mut (), lhs: Felt<C::F>, rhs: Felt<C::F>) -> Felt<C::F> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::AddF(res, lhs, rhs));

        res
    }

    fn sub_felt(ptr: *mut (), lhs: Felt<C::F>, rhs: Felt<C::F>) -> Felt<C::F> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::SubF(res, lhs, rhs));

        res
    }

    fn neg_felt(ptr: *mut (), lhs: Felt<C::F>) -> Felt<C::F> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::NegF(res, lhs));

        res
    }

    fn mul_felt(ptr: *mut (), lhs: Felt<C::F>, rhs: Felt<C::F>) -> Felt<C::F> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::MulF(res, lhs, rhs));

        res
    }

    fn add_felt_const(ptr: *mut (), lhs: Felt<C::F>, rhs: C::F) -> Felt<C::F> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::AddFI(res, lhs, rhs));

        res
    }

    fn sub_felt_const(ptr: *mut (), lhs: Felt<C::F>, rhs: C::F) -> Felt<C::F> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::SubFI(res, lhs, rhs));

        res
    }

    fn sub_const_felt(ptr: *mut (), lhs: C::F, rhs: Felt<C::F>) -> Felt<C::F> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, rhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::SubFIN(res, lhs, rhs));

        res
    }

    fn mul_const_felt(ptr: *mut (), lhs: Felt<C::F>, rhs: C::F) -> Felt<C::F> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::MulFI(res, lhs, rhs));

        res
    }

    fn div_felt(ptr: *mut (), lhs: Felt<C::F>, rhs: Felt<C::F>) -> Felt<C::F> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::DivF(res, lhs, rhs));

        res
    }

    fn div_felt_const(ptr: *mut (), lhs: Felt<C::F>, rhs: C::F) -> Felt<C::F> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::DivFI(res, lhs, rhs));

        res
    }

    fn div_const_felt(ptr: *mut (), lhs: C::F, rhs: Felt<C::F>) -> Felt<C::F> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Felt::new(idx, rhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::DivFIN(res, lhs, rhs));

        res
    }
}

impl<C: Config> ExtOperations<C::F, C::EF> for UnsafeCell<InnerBuilder<C>> {
    fn add_ext(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: Ext<C::F, C::EF>) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::AddE(res, lhs, rhs));

        res
    }

    fn add_ext_base(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: Felt<C::F>) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::AddEF(res, lhs, rhs));

        res
    }

    fn add_const_base(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: C::F) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::AddEFI(res, lhs, rhs));

        res
    }

    fn add_const_ext(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: C::EF) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::AddEI(res, lhs, rhs));

        res
    }

    fn add_felt_const_ext(
        ptr: *mut (),
        lhs: Felt<C::F>,
        rhs: C::EF,
        handle: *mut ExtHandle<C::F, C::EF>,
    ) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let idx = inner.get_mut().variable_count;
        let res = Ext::new(idx, handle);
        let inner = inner.get_mut();

        inner.variable_count += 1;
        inner.operations.push(DslIr::AddEFFI(res, lhs, rhs));

        res
    }

    fn sub_ext(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: Ext<C::F, C::EF>) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::SubE(res, lhs, rhs));

        res
    }

    fn sub_ext_base(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: Felt<C::F>) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::SubEF(res, lhs, rhs));

        res
    }

    fn sub_const_ext(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: C::EF) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::SubEI(res, lhs, rhs));

        res
    }

    fn sub_ext_const(ptr: *mut (), lhs: C::EF, rhs: Ext<C::F, C::EF>) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, rhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::SubEIN(res, lhs, rhs));

        res
    }

    fn sub_felt_const_ext(
        ptr: *mut (),
        lhs: Felt<C::F>,
        rhs: C::EF,
        handle: *mut ExtHandle<C::F, C::EF>,
    ) -> Ext<C::F, C::EF> {
        Self::add_felt_const_ext(ptr, lhs, -rhs, handle)
    }

    fn sub_base_ext(ptr: *mut (), lhs: Felt<C::F>, rhs: Ext<C::F, C::EF>) -> Ext<C::F, C::EF> {
        // TODO: optimize to one opcode.
        let rhs = Self::neg_ext(ptr, rhs);
        Self::add_ext_base(ptr, rhs, lhs)
    }

    fn neg_ext(ptr: *mut (), lhs: Ext<C::F, C::EF>) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::NegE(res, lhs));

        res
    }

    fn mul_ext(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: Ext<C::F, C::EF>) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::MulE(res, lhs, rhs));

        res
    }

    fn mul_ext_base(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: Felt<C::F>) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::MulEF(res, lhs, rhs));

        res
    }

    fn mul_const_ext(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: C::EF) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::MulEI(res, lhs, rhs));

        res
    }

    fn mul_felt_const_ext(
        ptr: *mut (),
        lhs: Felt<C::F>,
        rhs: C::EF,
        handle: *mut ExtHandle<C::F, C::EF>,
    ) -> Ext<C::F, C::EF> {
        // TODO: optimize to one opcode.
        let lhs = Self::add_felt_const_ext(ptr, lhs, C::EF::zero(), handle);
        Self::mul_const_ext(ptr, lhs, rhs)
    }

    fn div_ext(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: Ext<C::F, C::EF>) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::DivE(res, lhs, rhs));

        res
    }

    fn div_const_base(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: C::F) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::DivEFI(res, lhs, rhs));

        res
    }

    fn div_const_ext(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: C::EF) -> Ext<C::F, C::EF> {
        Self::mul_const_ext(ptr, lhs, rhs.inverse())
    }

    fn div_base_ext(ptr: *mut (), lhs: Felt<C::F>, rhs: Ext<C::F, C::EF>) -> Ext<C::F, C::EF> {
        // TODO: optimize to one opcode.
        let lhs = Self::add_felt_const_ext(ptr, lhs, C::EF::zero(), rhs.handle);
        Self::div_ext(ptr, lhs, rhs)
    }

    fn div_ext_base(ptr: *mut (), lhs: Ext<C::F, C::EF>, rhs: Felt<C::F>) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, lhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::DivEF(res, lhs, rhs));

        res
    }

    fn div_ext_const(ptr: *mut (), lhs: C::EF, rhs: Ext<C::F, C::EF>) -> Ext<C::F, C::EF> {
        let mut inner = unsafe { ManuallyDrop::new(Box::from_raw(ptr as *mut Self)) };
        let inner = inner.get_mut();
        let idx = inner.variable_count;
        let res = Ext::new(idx, rhs.handle);
        inner.variable_count += 1;

        inner.operations.push(DslIr::DivEIN(res, lhs, rhs));

        res
    }

    fn div_felt_const_ext(
        ptr: *mut (),
        lhs: Felt<C::F>,
        rhs: C::EF,
        handle: *mut ExtHandle<C::F, C::EF>,
    ) -> Ext<C::F, C::EF> {
        Self::mul_felt_const_ext(ptr, lhs, rhs.inverse(), handle)
    }
}

impl<N> VarHandle<N> {
    pub fn add_v(&self, lhs: Var<N>, rhs: Var<N>) -> Var<N> {
        (self.add_var)(self.ptr, lhs, rhs)
    }

    pub fn sub_v(&self, lhs: Var<N>, rhs: Var<N>) -> Var<N> {
        (self.sub_var)(self.ptr, lhs, rhs)
    }

    pub fn neg_v(&self, lhs: Var<N>) -> Var<N> {
        (self.neg_var)(self.ptr, lhs)
    }

    pub fn mul_v(&self, lhs: Var<N>, rhs: Var<N>) -> Var<N> {
        (self.mul_var)(self.ptr, lhs, rhs)
    }

    pub fn add_const_v(&self, lhs: Var<N>, rhs: N) -> Var<N> {
        (self.add_var_const)(self.ptr, lhs, rhs)
    }

    pub fn add_v_const(&self, lhs: N, rhs: Var<N>) -> Var<N> {
        self.add_const_v(rhs, lhs)
    }

    pub fn mul_const_v(&self, lhs: Var<N>, rhs: N) -> Var<N> {
        (self.mul_var_const)(self.ptr, lhs, rhs)
    }

    pub fn mul_v_const(&self, lhs: N, rhs: Var<N>) -> Var<N> {
        self.mul_const_v(rhs, lhs)
    }

    pub fn sub_const_v(&self, lhs: N, rhs: Var<N>) -> Var<N> {
        (self.sub_const_var)(self.ptr, lhs, rhs)
    }

    pub fn sub_v_const(&self, lhs: Var<N>, rhs: N) -> Var<N> {
        (self.sub_var_const)(self.ptr, lhs, rhs)
    }
}

impl<F> FeltHandle<F> {
    pub fn add_f(&self, lhs: Felt<F>, rhs: Felt<F>) -> Felt<F> {
        (self.add_felt)(self.ptr, lhs, rhs)
    }

    pub fn add_const_f(&self, lhs: Felt<F>, rhs: F) -> Felt<F> {
        (self.add_const_felt)(self.ptr, lhs, rhs)
    }

    pub fn add_f_const(&self, lhs: F, rhs: Felt<F>) -> Felt<F> {
        self.add_const_f(rhs, lhs)
    }

    pub fn sub_f(&self, lhs: Felt<F>, rhs: Felt<F>) -> Felt<F> {
        (self.sub_felt)(self.ptr, lhs, rhs)
    }

    pub fn sub_f_const(&self, lhs: Felt<F>, rhs: F) -> Felt<F> {
        (self.sub_felt_const)(self.ptr, lhs, rhs)
    }

    pub fn sub_const_f(&self, lhs: F, rhs: Felt<F>) -> Felt<F> {
        (self.sub_const_felt)(self.ptr, lhs, rhs)
    }

    pub fn neg_f(&self, lhs: Felt<F>) -> Felt<F> {
        (self.neg_felt)(self.ptr, lhs)
    }

    pub fn mul_f(&self, lhs: Felt<F>, rhs: Felt<F>) -> Felt<F> {
        (self.mul_felt)(self.ptr, lhs, rhs)
    }

    pub fn mul_const_f(&self, lhs: Felt<F>, rhs: F) -> Felt<F> {
        (self.mul_felt_const)(self.ptr, lhs, rhs)
    }

    pub fn mul_f_const(&self, lhs: F, rhs: Felt<F>) -> Felt<F> {
        self.mul_const_f(rhs, lhs)
    }

    pub fn div_f(&self, lhs: Felt<F>, rhs: Felt<F>) -> Felt<F> {
        (self.div_felt)(self.ptr, lhs, rhs)
    }

    pub fn div_f_const(&self, lhs: Felt<F>, rhs: F) -> Felt<F> {
        (self.div_felt_const)(self.ptr, lhs, rhs)
    }

    pub fn div_const_f(&self, lhs: F, rhs: Felt<F>) -> Felt<F> {
        (self.div_const_felt)(self.ptr, lhs, rhs)
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> ExtHandle<F, EF> {
    pub fn add_e(&self, lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF> {
        (self.add_ext)(self.ptr, lhs, rhs)
    }

    pub fn add_e_f(&self, lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF> {
        (self.add_ext_base)(self.ptr, lhs, rhs)
    }

    pub fn add_f_e(&self, lhs: Felt<F>, rhs: Ext<F, EF>) -> Ext<F, EF> {
        self.add_e_f(rhs, lhs)
    }

    pub fn add_e_const_f(&self, lhs: Ext<F, EF>, rhs: F) -> Ext<F, EF> {
        (self.add_const_base)(self.ptr, lhs, rhs)
    }

    pub fn add_f_const_e(
        &self,
        lhs: Felt<F>,
        rhs: EF,
        handle: *mut ExtHandle<F, EF>,
    ) -> Ext<F, EF> {
        (self.add_felt_const_ext)(self.ptr, lhs, rhs, handle)
    }

    pub fn add_const_e_f(
        &self,
        lhs: EF,
        rhs: Felt<F>,
        handle: *mut ExtHandle<F, EF>,
    ) -> Ext<F, EF> {
        self.add_f_const_e(rhs, lhs, handle)
    }

    pub fn add_const_e(&self, lhs: Ext<F, EF>, rhs: EF) -> Ext<F, EF> {
        (self.add_const_ext)(self.ptr, lhs, rhs)
    }

    pub fn add_e_const(&self, lhs: EF, rhs: Ext<F, EF>) -> Ext<F, EF> {
        (self.add_const_ext)(self.ptr, rhs, lhs)
    }

    pub fn sub_e(&self, lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF> {
        (self.sub_ext)(self.ptr, lhs, rhs)
    }

    pub fn sub_e_f(&self, lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF> {
        (self.sub_ext_base)(self.ptr, lhs, rhs)
    }

    pub fn sub_f_e(&self, lhs: Felt<F>, rhs: Ext<F, EF>) -> Ext<F, EF> {
        (self.sub_base_ext)(self.ptr, lhs, rhs)
    }

    pub fn sub_e_const_f(&self, lhs: Ext<F, EF>, rhs: F) -> Ext<F, EF> {
        (self.sub_const_ext)(self.ptr, lhs, EF::from_base(rhs))
    }

    pub fn sub_f_const_e(
        &self,
        lhs: Felt<F>,
        rhs: EF,
        handle: *mut ExtHandle<F, EF>,
    ) -> Ext<F, EF> {
        (self.sub_felt_const_ext)(self.ptr, lhs, rhs, handle)
    }

    pub fn sub_const_e_f(
        &self,
        lhs: EF,
        rhs: Felt<F>,
        handle: *mut ExtHandle<F, EF>,
    ) -> Ext<F, EF> {
        // TODO: optimize to one opcode.
        let rhs = self.add_f_const_e(rhs, EF::zero(), handle);
        self.sub_e_const(lhs, rhs)
    }

    pub fn sub_const_e(&self, lhs: Ext<F, EF>, rhs: EF) -> Ext<F, EF> {
        (self.sub_const_ext)(self.ptr, lhs, rhs)
    }

    pub fn sub_e_const(&self, lhs: EF, rhs: Ext<F, EF>) -> Ext<F, EF> {
        (self.sub_ext_const)(self.ptr, lhs, rhs)
    }

    pub fn neg_e(&self, lhs: Ext<F, EF>) -> Ext<F, EF> {
        (self.neg_ext)(self.ptr, lhs)
    }

    pub fn mul_e(&self, lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF> {
        (self.mul_ext)(self.ptr, lhs, rhs)
    }

    pub fn mul_e_f(&self, lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF> {
        (self.mul_ext_base)(self.ptr, lhs, rhs)
    }

    pub fn mul_f_e(&self, lhs: Felt<F>, rhs: Ext<F, EF>) -> Ext<F, EF> {
        self.mul_e_f(rhs, lhs)
    }

    pub fn mul_e_const_f(&self, lhs: Ext<F, EF>, rhs: F) -> Ext<F, EF> {
        (self.mul_const_ext)(self.ptr, lhs, EF::from_base(rhs))
    }

    pub fn mul_f_const_e(
        &self,
        lhs: Felt<F>,
        rhs: EF,
        handle: *mut ExtHandle<F, EF>,
    ) -> Ext<F, EF> {
        (self.mul_felt_const_ext)(self.ptr, lhs, rhs, handle)
    }

    pub fn mul_const_e_f(
        &self,
        lhs: EF,
        rhs: Felt<F>,
        handle: *mut ExtHandle<F, EF>,
    ) -> Ext<F, EF> {
        self.mul_f_const_e(rhs, lhs, handle)
    }

    pub fn mul_const_e(&self, lhs: Ext<F, EF>, rhs: EF) -> Ext<F, EF> {
        (self.mul_const_ext)(self.ptr, lhs, rhs)
    }

    pub fn mul_e_const(&self, lhs: EF, rhs: Ext<F, EF>) -> Ext<F, EF> {
        (self.mul_const_ext)(self.ptr, rhs, lhs)
    }

    pub fn div_e(&self, lhs: Ext<F, EF>, rhs: Ext<F, EF>) -> Ext<F, EF> {
        (self.div_ext)(self.ptr, lhs, rhs)
    }

    pub fn div_e_f(&self, lhs: Ext<F, EF>, rhs: Felt<F>) -> Ext<F, EF> {
        (self.div_ext_base)(self.ptr, lhs, rhs)
    }

    pub fn div_f_e(&self, lhs: Felt<F>, rhs: Ext<F, EF>) -> Ext<F, EF> {
        (self.div_base_ext)(self.ptr, lhs, rhs)
    }

    pub fn div_e_const_f(&self, lhs: Ext<F, EF>, rhs: F) -> Ext<F, EF> {
        (self.div_const_base)(self.ptr, lhs, rhs)
    }

    pub fn div_f_const_e(
        &self,
        lhs: Felt<F>,
        rhs: EF,
        handle: *mut ExtHandle<F, EF>,
    ) -> Ext<F, EF> {
        (self.div_felt_const_ext)(self.ptr, lhs, rhs, handle)
    }

    pub fn div_const_e(&self, lhs: Ext<F, EF>, rhs: EF) -> Ext<F, EF> {
        (self.div_const_ext)(self.ptr, lhs, rhs)
    }

    pub fn div_e_const(&self, lhs: EF, rhs: Ext<F, EF>) -> Ext<F, EF> {
        (self.div_ext_const)(self.ptr, lhs, rhs)
    }
}
