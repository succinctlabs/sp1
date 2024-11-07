use core::{
    any::Any,
    ops::{Add, Div, Mul, Neg, Sub},
};
use std::{
    any::TypeId,
    iter::{Product, Sum},
    mem::{self, ManuallyDrop},
    ops::{AddAssign, DivAssign, MulAssign, SubAssign},
};

use p3_field::{AbstractField, ExtensionField, Field};

use crate::ir::ExtHandle;

use super::{Ext, Felt, Usize, Var};

#[derive(Debug, Clone, Copy)]
pub enum SymbolicVar<N: Field> {
    Const(N),
    Val(Var<N>),
}

#[derive(Debug, Clone, Copy)]
pub enum SymbolicFelt<F: Field> {
    Const(F),
    Val(Felt<F>),
}

#[derive(Debug, Clone, Copy)]
pub enum SymbolicExt<F: Field, EF: Field> {
    Const(EF),
    Base(SymbolicFelt<F>),
    Val(Ext<F, EF>),
}

#[derive(Debug, Clone, Copy)]
pub enum SymbolicUsize<N: Field> {
    Const(usize),
    Var(SymbolicVar<N>),
}

#[derive(Debug, Clone)]
pub enum ExtOperand<F: Field, EF: ExtensionField<F>> {
    Base(F),
    Const(EF),
    Felt(Felt<F>),
    Ext(Ext<F, EF>),
    SymFelt(SymbolicFelt<F>),
    Sym(SymbolicExt<F, EF>),
}

impl<F: Field, EF: ExtensionField<F>> ExtOperand<F, EF> {
    pub fn symbolic(self) -> SymbolicExt<F, EF> {
        match self {
            ExtOperand::Base(f) => SymbolicExt::Base(SymbolicFelt::from(f)),
            ExtOperand::Const(ef) => SymbolicExt::Const(ef),
            ExtOperand::Felt(f) => SymbolicExt::Base(SymbolicFelt::from(f)),
            ExtOperand::Ext(e) => SymbolicExt::Val(e),
            ExtOperand::SymFelt(f) => SymbolicExt::Base(f),
            ExtOperand::Sym(e) => e,
        }
    }
}

pub trait ExtConst<F: Field, EF: ExtensionField<F>> {
    fn cons(self) -> SymbolicExt<F, EF>;
}

impl<F: Field, EF: ExtensionField<F>> ExtConst<F, EF> for EF {
    fn cons(self) -> SymbolicExt<F, EF> {
        SymbolicExt::Const(self)
    }
}

pub trait ExtensionOperand<F: Field, EF: ExtensionField<F>> {
    fn to_operand(self) -> ExtOperand<F, EF>;
}

impl<N: Field> AbstractField for SymbolicVar<N> {
    type F = N;

    fn zero() -> Self {
        SymbolicVar::from(N::zero())
    }

    fn one() -> Self {
        SymbolicVar::from(N::one())
    }

    fn two() -> Self {
        SymbolicVar::from(N::two())
    }

    fn neg_one() -> Self {
        SymbolicVar::from(N::neg_one())
    }

    fn from_f(f: Self::F) -> Self {
        SymbolicVar::from(f)
    }
    fn from_bool(b: bool) -> Self {
        SymbolicVar::from(N::from_bool(b))
    }
    fn from_canonical_u8(n: u8) -> Self {
        SymbolicVar::from(N::from_canonical_u8(n))
    }
    fn from_canonical_u16(n: u16) -> Self {
        SymbolicVar::from(N::from_canonical_u16(n))
    }
    fn from_canonical_u32(n: u32) -> Self {
        SymbolicVar::from(N::from_canonical_u32(n))
    }
    fn from_canonical_u64(n: u64) -> Self {
        SymbolicVar::from(N::from_canonical_u64(n))
    }
    fn from_canonical_usize(n: usize) -> Self {
        SymbolicVar::from(N::from_canonical_usize(n))
    }

    fn from_wrapped_u32(n: u32) -> Self {
        SymbolicVar::from(N::from_wrapped_u32(n))
    }
    fn from_wrapped_u64(n: u64) -> Self {
        SymbolicVar::from(N::from_wrapped_u64(n))
    }

    /// A generator of this field's entire multiplicative group.
    fn generator() -> Self {
        SymbolicVar::from(N::generator())
    }
}

impl<F: Field> AbstractField for SymbolicFelt<F> {
    type F = F;

    fn zero() -> Self {
        SymbolicFelt::from(F::zero())
    }

    fn one() -> Self {
        SymbolicFelt::from(F::one())
    }

    fn two() -> Self {
        SymbolicFelt::from(F::two())
    }

    fn neg_one() -> Self {
        SymbolicFelt::from(F::neg_one())
    }

    fn from_f(f: Self::F) -> Self {
        SymbolicFelt::from(f)
    }
    fn from_bool(b: bool) -> Self {
        SymbolicFelt::from(F::from_bool(b))
    }
    fn from_canonical_u8(n: u8) -> Self {
        SymbolicFelt::from(F::from_canonical_u8(n))
    }
    fn from_canonical_u16(n: u16) -> Self {
        SymbolicFelt::from(F::from_canonical_u16(n))
    }
    fn from_canonical_u32(n: u32) -> Self {
        SymbolicFelt::from(F::from_canonical_u32(n))
    }
    fn from_canonical_u64(n: u64) -> Self {
        SymbolicFelt::from(F::from_canonical_u64(n))
    }
    fn from_canonical_usize(n: usize) -> Self {
        SymbolicFelt::from(F::from_canonical_usize(n))
    }

    fn from_wrapped_u32(n: u32) -> Self {
        SymbolicFelt::from(F::from_wrapped_u32(n))
    }
    fn from_wrapped_u64(n: u64) -> Self {
        SymbolicFelt::from(F::from_wrapped_u64(n))
    }

    /// A generator of this field's entire multiplicative group.
    fn generator() -> Self {
        SymbolicFelt::from(F::generator())
    }
}

impl<F: Field, EF: ExtensionField<F>> AbstractField for SymbolicExt<F, EF> {
    type F = EF;

    fn zero() -> Self {
        SymbolicExt::from_f(EF::zero())
    }

    fn one() -> Self {
        SymbolicExt::from_f(EF::one())
    }

    fn two() -> Self {
        SymbolicExt::from_f(EF::two())
    }

    fn neg_one() -> Self {
        SymbolicExt::from_f(EF::neg_one())
    }

    fn from_f(f: Self::F) -> Self {
        SymbolicExt::Const(f)
    }
    fn from_bool(b: bool) -> Self {
        SymbolicExt::from_f(EF::from_bool(b))
    }
    fn from_canonical_u8(n: u8) -> Self {
        SymbolicExt::from_f(EF::from_canonical_u8(n))
    }
    fn from_canonical_u16(n: u16) -> Self {
        SymbolicExt::from_f(EF::from_canonical_u16(n))
    }
    fn from_canonical_u32(n: u32) -> Self {
        SymbolicExt::from_f(EF::from_canonical_u32(n))
    }
    fn from_canonical_u64(n: u64) -> Self {
        SymbolicExt::from_f(EF::from_canonical_u64(n))
    }
    fn from_canonical_usize(n: usize) -> Self {
        SymbolicExt::from_f(EF::from_canonical_usize(n))
    }

    fn from_wrapped_u32(n: u32) -> Self {
        SymbolicExt::from_f(EF::from_wrapped_u32(n))
    }
    fn from_wrapped_u64(n: u64) -> Self {
        SymbolicExt::from_f(EF::from_wrapped_u64(n))
    }

    /// A generator of this field's entire multiplicative group.
    fn generator() -> Self {
        SymbolicExt::from_f(EF::generator())
    }
}

// Implement all conversions from constants N, F, EF, to the corresponding symbolic types

impl<N: Field> From<N> for SymbolicVar<N> {
    fn from(n: N) -> Self {
        SymbolicVar::Const(n)
    }
}

impl<F: Field> From<F> for SymbolicFelt<F> {
    fn from(f: F) -> Self {
        SymbolicFelt::Const(f)
    }
}

impl<F: Field, EF: ExtensionField<F>> From<F> for SymbolicExt<F, EF> {
    fn from(f: F) -> Self {
        f.to_operand().symbolic()
    }
}

// Implement all conversions from Var<N>, Felt<F>, Ext<F, EF> to the corresponding symbolic types

impl<N: Field> From<Var<N>> for SymbolicVar<N> {
    fn from(v: Var<N>) -> Self {
        SymbolicVar::Val(v)
    }
}

impl<F: Field> From<Felt<F>> for SymbolicFelt<F> {
    fn from(f: Felt<F>) -> Self {
        SymbolicFelt::Val(f)
    }
}

impl<F: Field, EF: ExtensionField<F>> From<Ext<F, EF>> for SymbolicExt<F, EF> {
    fn from(e: Ext<F, EF>) -> Self {
        e.to_operand().symbolic()
    }
}

// Implement all operations for SymbolicVar<N>, SymbolicFelt<F>, SymbolicExt<F, EF>

impl<N: Field> Add for SymbolicVar<N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::Const(lhs), Self::Const(rhs)) => Self::Const(lhs + rhs),
            (Self::Val(lhs), Self::Const(rhs)) => {
                let res = unsafe { (*lhs.handle).add_const_v(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Const(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*rhs.handle).add_v_const(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Val(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*lhs.handle).add_v(lhs, rhs) };
                Self::Val(res)
            }
        }
    }
}

impl<F: Field> Add for SymbolicFelt<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::Const(lhs), Self::Const(rhs)) => Self::Const(lhs + rhs),
            (Self::Val(lhs), Self::Const(rhs)) => {
                let res = unsafe { (*lhs.handle).add_const_f(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Const(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*rhs.handle).add_f_const(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Val(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*lhs.handle).add_f(lhs, rhs) };
                Self::Val(res)
            }
        }
    }
}

impl<F: Field, EF: ExtensionField<F>, E: ExtensionOperand<F, EF>> Add<E> for SymbolicExt<F, EF> {
    type Output = Self;

    fn add(self, rhs: E) -> Self::Output {
        let rhs = rhs.to_operand().symbolic();

        match (self, rhs) {
            (Self::Const(lhs), Self::Const(rhs)) => Self::Const(lhs + rhs),
            (Self::Val(lhs), Self::Const(rhs)) => {
                let res = unsafe { (*lhs.handle).add_const_e(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Const(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*rhs.handle).add_e_const(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Const(lhs), Self::Base(rhs)) => match rhs {
                SymbolicFelt::Const(rhs) => Self::Const(lhs + rhs),
                SymbolicFelt::Val(rhs) => {
                    let ext_handle_ptr =
                        unsafe { (*rhs.handle).ext_handle_ptr as *mut ExtHandle<F, EF> };
                    let ext_handle: ManuallyDrop<_> =
                        unsafe { ManuallyDrop::new(Box::from_raw(ext_handle_ptr)) };
                    let res = ext_handle.add_const_e_f(lhs, rhs, ext_handle_ptr);
                    Self::Val(res)
                }
            },
            (Self::Base(lhs), Self::Const(rhs)) => match lhs {
                SymbolicFelt::Const(lhs) => Self::Const(rhs + lhs),
                SymbolicFelt::Val(lhs) => {
                    let ext_handle_ptr =
                        unsafe { (*lhs.handle).ext_handle_ptr as *mut ExtHandle<F, EF> };
                    let ext_handle: ManuallyDrop<_> =
                        unsafe { ManuallyDrop::new(Box::from_raw(ext_handle_ptr)) };
                    let res = ext_handle.add_f_const_e(lhs, rhs, ext_handle_ptr);
                    Self::Val(res)
                }
            },

            (Self::Val(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*lhs.handle).add_e(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Base(lhs), Self::Base(rhs)) => Self::Base(lhs + rhs),
            (Self::Base(lhs), Self::Val(rhs)) => match lhs {
                SymbolicFelt::Const(lhs) => {
                    let res = unsafe { (*rhs.handle).add_e_const(EF::from_base(lhs), rhs) };
                    Self::Val(res)
                }
                SymbolicFelt::Val(lhs) => {
                    let res = unsafe { (*rhs.handle).add_f_e(lhs, rhs) };
                    Self::Val(res)
                }
            },
            (Self::Val(lhs), Self::Base(rhs)) => match rhs {
                SymbolicFelt::Const(rhs) => {
                    let res = unsafe { (*lhs.handle).add_const_e(lhs, EF::from_base(rhs)) };
                    Self::Val(res)
                }
                SymbolicFelt::Val(rhs) => {
                    let res = unsafe { (*lhs.handle).add_e_f(lhs, rhs) };
                    Self::Val(res)
                }
            },
        }
    }
}

impl<N: Field> Mul for SymbolicVar<N> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::Const(lhs), Self::Const(rhs)) => Self::Const(lhs * rhs),
            (Self::Val(lhs), Self::Const(rhs)) => {
                let res = unsafe { (*lhs.handle).mul_const_v(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Const(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*rhs.handle).mul_v_const(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Val(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*lhs.handle).mul_v(lhs, rhs) };
                Self::Val(res)
            }
        }
    }
}

impl<F: Field> Mul for SymbolicFelt<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::Const(lhs), Self::Const(rhs)) => Self::Const(lhs * rhs),
            (Self::Val(lhs), Self::Const(rhs)) => {
                let res = unsafe { (*lhs.handle).mul_const_f(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Const(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*rhs.handle).mul_f_const(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Val(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*lhs.handle).mul_f(lhs, rhs) };
                Self::Val(res)
            }
        }
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Mul<E> for SymbolicExt<F, EF> {
    type Output = Self;

    fn mul(self, rhs: E) -> Self::Output {
        let rhs = rhs.to_operand().symbolic();

        match (self, rhs) {
            (Self::Const(lhs), Self::Const(rhs)) => Self::Const(lhs * rhs),
            (Self::Val(lhs), Self::Const(rhs)) => {
                let res = unsafe { (*lhs.handle).mul_const_e(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Const(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*rhs.handle).mul_e_const(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Const(lhs), Self::Base(rhs)) => match rhs {
                SymbolicFelt::Const(rhs) => Self::Const(lhs * rhs),
                SymbolicFelt::Val(rhs) => {
                    let ext_handle_ptr =
                        unsafe { (*rhs.handle).ext_handle_ptr as *mut ExtHandle<F, EF> };
                    let ext_handle: ManuallyDrop<_> =
                        unsafe { ManuallyDrop::new(Box::from_raw(ext_handle_ptr)) };
                    let res = ext_handle.mul_const_e_f(lhs, rhs, ext_handle_ptr);
                    Self::Val(res)
                }
            },
            (Self::Base(lhs), Self::Const(rhs)) => match lhs {
                SymbolicFelt::Const(lhs) => Self::Const(EF::from_base(lhs) * rhs),
                SymbolicFelt::Val(lhs) => {
                    let ext_handle_ptr =
                        unsafe { (*lhs.handle).ext_handle_ptr as *mut ExtHandle<F, EF> };
                    let ext_handle: ManuallyDrop<_> =
                        unsafe { ManuallyDrop::new(Box::from_raw(ext_handle_ptr)) };
                    let res = ext_handle.mul_f_const_e(lhs, rhs, ext_handle_ptr);
                    Self::Val(res)
                }
            },

            (Self::Val(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*lhs.handle).mul_e(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Base(lhs), Self::Base(rhs)) => Self::Base(lhs * rhs),
            (Self::Base(lhs), Self::Val(rhs)) => match lhs {
                SymbolicFelt::Const(lhs) => {
                    let res = unsafe { (*rhs.handle).mul_e_const(EF::from_base(lhs), rhs) };
                    Self::Val(res)
                }
                SymbolicFelt::Val(lhs) => {
                    let res = unsafe { (*rhs.handle).mul_f_e(lhs, rhs) };
                    Self::Val(res)
                }
            },
            (Self::Val(lhs), Self::Base(rhs)) => match rhs {
                SymbolicFelt::Const(rhs) => {
                    let res = unsafe { (*lhs.handle).mul_const_e(lhs, EF::from_base(rhs)) };
                    Self::Val(res)
                }
                SymbolicFelt::Val(rhs) => {
                    let res = unsafe { (*lhs.handle).mul_e_f(lhs, rhs) };
                    Self::Val(res)
                }
            },
        }
    }
}

impl<N: Field> Sub for SymbolicVar<N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::Const(lhs), Self::Const(rhs)) => Self::Const(lhs - rhs),
            (Self::Val(lhs), Self::Const(rhs)) => {
                let res = unsafe { (*lhs.handle).sub_v_const(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Const(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*rhs.handle).sub_const_v(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Val(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*lhs.handle).sub_v(lhs, rhs) };
                Self::Val(res)
            }
        }
    }
}

impl<F: Field> Sub for SymbolicFelt<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::Const(lhs), Self::Const(rhs)) => Self::Const(lhs - rhs),
            (Self::Val(lhs), Self::Const(rhs)) => {
                let res = unsafe { (*lhs.handle).sub_f_const(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Const(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*rhs.handle).sub_const_f(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Val(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*lhs.handle).sub_f(lhs, rhs) };
                Self::Val(res)
            }
        }
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Sub<E> for SymbolicExt<F, EF> {
    type Output = Self;

    fn sub(self, rhs: E) -> Self::Output {
        let rhs = rhs.to_operand().symbolic();

        match (self, rhs) {
            (Self::Const(lhs), Self::Const(rhs)) => Self::Const(lhs - rhs),
            (Self::Val(lhs), Self::Const(rhs)) => {
                let res = unsafe { (*lhs.handle).sub_const_e(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Const(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*rhs.handle).sub_e_const(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Const(lhs), Self::Base(rhs)) => match rhs {
                SymbolicFelt::Const(rhs) => Self::Const(lhs - rhs),
                SymbolicFelt::Val(rhs) => {
                    let ext_handle_ptr =
                        unsafe { (*rhs.handle).ext_handle_ptr as *mut ExtHandle<F, EF> };
                    let ext_handle: ManuallyDrop<_> =
                        unsafe { ManuallyDrop::new(Box::from_raw(ext_handle_ptr)) };
                    let res = ext_handle.sub_const_e_f(lhs, rhs, ext_handle_ptr);
                    Self::Val(res)
                }
            },
            (Self::Base(lhs), Self::Const(rhs)) => match lhs {
                SymbolicFelt::Const(lhs) => Self::Const(EF::from_base(lhs) - rhs),
                SymbolicFelt::Val(lhs) => {
                    let ext_handle_ptr =
                        unsafe { (*lhs.handle).ext_handle_ptr as *mut ExtHandle<F, EF> };
                    let ext_handle: ManuallyDrop<_> =
                        unsafe { ManuallyDrop::new(Box::from_raw(ext_handle_ptr)) };
                    let res = ext_handle.sub_f_const_e(lhs, rhs, ext_handle_ptr);
                    Self::Val(res)
                }
            },

            (Self::Val(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*lhs.handle).sub_e(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Base(lhs), Self::Base(rhs)) => Self::Base(lhs - rhs),
            (Self::Base(lhs), Self::Val(rhs)) => match lhs {
                SymbolicFelt::Const(lhs) => {
                    let res = unsafe { (*rhs.handle).sub_e_const(EF::from_base(lhs), rhs) };
                    Self::Val(res)
                }
                SymbolicFelt::Val(lhs) => {
                    let res = unsafe { (*rhs.handle).sub_f_e(lhs, rhs) };
                    Self::Val(res)
                }
            },
            (Self::Val(lhs), Self::Base(rhs)) => match rhs {
                SymbolicFelt::Const(rhs) => {
                    let res = unsafe { (*lhs.handle).sub_const_e(lhs, EF::from_base(rhs)) };
                    Self::Val(res)
                }
                SymbolicFelt::Val(rhs) => {
                    let res = unsafe { (*lhs.handle).sub_e_f(lhs, rhs) };
                    Self::Val(res)
                }
            },
        }
    }
}

impl<F: Field> Div for SymbolicFelt<F> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::Const(lhs), Self::Const(rhs)) => Self::Const(lhs / rhs),
            (Self::Val(lhs), Self::Const(rhs)) => {
                let res = unsafe { (*lhs.handle).div_f_const(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Const(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*rhs.handle).div_const_f(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Val(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*lhs.handle).div_f(lhs, rhs) };
                Self::Val(res)
            }
        }
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Div<E> for SymbolicExt<F, EF> {
    type Output = Self;

    fn div(self, rhs: E) -> Self::Output {
        let rhs = rhs.to_operand().symbolic();

        match (self, rhs) {
            (Self::Const(lhs), Self::Const(rhs)) => Self::Const(lhs / rhs),
            (Self::Val(lhs), Self::Const(rhs)) => {
                let res = unsafe { (*lhs.handle).div_const_e(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Const(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*rhs.handle).div_e_const(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Const(lhs), Self::Base(rhs)) => match rhs {
                SymbolicFelt::Const(rhs) => Self::Const(lhs / EF::from_base(rhs)),
                SymbolicFelt::Val(rhs) => {
                    let ext_handle_ptr =
                        unsafe { (*rhs.handle).ext_handle_ptr as *mut ExtHandle<F, EF> };
                    let ext_handle: ManuallyDrop<_> =
                        unsafe { ManuallyDrop::new(Box::from_raw(ext_handle_ptr)) };
                    let rhs = rhs.inverse();
                    if let SymbolicFelt::Val(rhs) = rhs {
                        let res = ext_handle.mul_const_e_f(lhs, rhs, ext_handle_ptr);
                        Self::Val(res)
                    } else {
                        unreachable!()
                    }
                }
            },
            (Self::Base(lhs), Self::Const(rhs)) => match lhs {
                SymbolicFelt::Const(lhs) => Self::Const(EF::from_base(lhs) / rhs),
                SymbolicFelt::Val(lhs) => {
                    let ext_handle_ptr =
                        unsafe { (*lhs.handle).ext_handle_ptr as *mut ExtHandle<F, EF> };
                    let ext_handle: ManuallyDrop<_> =
                        unsafe { ManuallyDrop::new(Box::from_raw(ext_handle_ptr)) };
                    let res = ext_handle.div_f_const_e(lhs, rhs, ext_handle_ptr);
                    Self::Val(res)
                }
            },

            (Self::Val(lhs), Self::Val(rhs)) => {
                let res = unsafe { (*lhs.handle).div_e(lhs, rhs) };
                Self::Val(res)
            }
            (Self::Base(lhs), Self::Base(rhs)) => Self::Base(lhs / rhs),
            (Self::Base(lhs), Self::Val(rhs)) => match lhs {
                SymbolicFelt::Const(lhs) => {
                    let res = unsafe { (*rhs.handle).div_e_const(EF::from_base(lhs), rhs) };
                    Self::Val(res)
                }
                SymbolicFelt::Val(lhs) => {
                    let res = unsafe { (*rhs.handle).div_f_e(lhs, rhs) };
                    Self::Val(res)
                }
            },
            (Self::Val(lhs), Self::Base(rhs)) => match rhs {
                SymbolicFelt::Const(rhs) => {
                    let res = unsafe { (*lhs.handle).div_const_e(lhs, EF::from_base(rhs)) };
                    Self::Val(res)
                }
                SymbolicFelt::Val(rhs) => {
                    let res = unsafe { (*lhs.handle).div_e_f(lhs, rhs) };
                    Self::Val(res)
                }
            },
        }
    }
}

impl<N: Field> Neg for SymbolicVar<N> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        match self {
            SymbolicVar::Const(n) => SymbolicVar::Const(-n),
            SymbolicVar::Val(n) => {
                let res = unsafe { (*n.handle).neg_v(n) };
                SymbolicVar::Val(res)
            }
        }
    }
}

impl<F: Field> Neg for SymbolicFelt<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        match self {
            SymbolicFelt::Const(f) => SymbolicFelt::Const(-f),
            SymbolicFelt::Val(f) => {
                let res = unsafe { (*f.handle).neg_f(f) };
                SymbolicFelt::Val(res)
            }
        }
    }
}

impl<F: Field, EF: ExtensionField<F>> Neg for SymbolicExt<F, EF> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        match self {
            SymbolicExt::Const(ef) => SymbolicExt::Const(-ef),
            SymbolicExt::Base(f) => SymbolicExt::Base(-f),
            SymbolicExt::Val(ef) => {
                let res = unsafe { (*ef.handle).neg_e(ef) };
                SymbolicExt::Val(res)
            }
        }
    }
}

// Implement all operations between N, F, EF, and SymbolicVar<N>, SymbolicFelt<F>, SymbolicExt<F,
// EF>

impl<N: Field> Add<N> for SymbolicVar<N> {
    type Output = Self;

    fn add(self, rhs: N) -> Self::Output {
        self + SymbolicVar::from(rhs)
    }
}

impl<F: Field> Add<F> for SymbolicFelt<F> {
    type Output = Self;

    fn add(self, rhs: F) -> Self::Output {
        self + SymbolicFelt::from(rhs)
    }
}

impl<N: Field> Mul<N> for SymbolicVar<N> {
    type Output = Self;

    fn mul(self, rhs: N) -> Self::Output {
        self * SymbolicVar::from(rhs)
    }
}

impl<F: Field> Mul<F> for SymbolicFelt<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        self * SymbolicFelt::from(rhs)
    }
}

impl<N: Field> Sub<N> for SymbolicVar<N> {
    type Output = Self;

    fn sub(self, rhs: N) -> Self::Output {
        self - SymbolicVar::from(rhs)
    }
}

impl<F: Field> Sub<F> for SymbolicFelt<F> {
    type Output = Self;

    fn sub(self, rhs: F) -> Self::Output {
        self - SymbolicFelt::from(rhs)
    }
}

// Implement all operations between SymbolicVar<N>, SymbolicFelt<F>, SymbolicExt<F, EF>, and Var<N>,
//  Felt<F>, Ext<F, EF>.

impl<N: Field> Add<Var<N>> for SymbolicVar<N> {
    type Output = SymbolicVar<N>;

    fn add(self, rhs: Var<N>) -> Self::Output {
        self + SymbolicVar::from(rhs)
    }
}

impl<F: Field> Add<Felt<F>> for SymbolicFelt<F> {
    type Output = SymbolicFelt<F>;

    fn add(self, rhs: Felt<F>) -> Self::Output {
        self + SymbolicFelt::from(rhs)
    }
}

impl<N: Field> Mul<Var<N>> for SymbolicVar<N> {
    type Output = SymbolicVar<N>;

    fn mul(self, rhs: Var<N>) -> Self::Output {
        self * SymbolicVar::from(rhs)
    }
}

impl<F: Field> Mul<Felt<F>> for SymbolicFelt<F> {
    type Output = SymbolicFelt<F>;

    fn mul(self, rhs: Felt<F>) -> Self::Output {
        self * SymbolicFelt::from(rhs)
    }
}

impl<N: Field> Sub<Var<N>> for SymbolicVar<N> {
    type Output = SymbolicVar<N>;

    fn sub(self, rhs: Var<N>) -> Self::Output {
        self - SymbolicVar::from(rhs)
    }
}

impl<F: Field> Sub<Felt<F>> for SymbolicFelt<F> {
    type Output = SymbolicFelt<F>;

    fn sub(self, rhs: Felt<F>) -> Self::Output {
        self - SymbolicFelt::from(rhs)
    }
}

impl<F: Field> Div<SymbolicFelt<F>> for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn div(self, rhs: SymbolicFelt<F>) -> Self::Output {
        SymbolicFelt::<F>::from(self) / rhs
    }
}

// Implement operations between constants N, F, EF, and Var<N>, Felt<F>, Ext<F, EF>.

impl<N: Field> Add for Var<N> {
    type Output = SymbolicVar<N>;

    fn add(self, rhs: Self) -> Self::Output {
        SymbolicVar::<N>::from(self) + rhs
    }
}

impl<N: Field> Add<N> for Var<N> {
    type Output = SymbolicVar<N>;

    fn add(self, rhs: N) -> Self::Output {
        SymbolicVar::from(self) + rhs
    }
}

impl<F: Field> Add for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn add(self, rhs: Self) -> Self::Output {
        SymbolicFelt::<F>::from(self) + rhs
    }
}

impl<F: Field> Add<F> for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn add(self, rhs: F) -> Self::Output {
        SymbolicFelt::from(self) + rhs
    }
}

impl<N: Field> Mul for Var<N> {
    type Output = SymbolicVar<N>;

    fn mul(self, rhs: Self) -> Self::Output {
        SymbolicVar::<N>::from(self) * rhs
    }
}

impl<N: Field> Mul<N> for Var<N> {
    type Output = SymbolicVar<N>;

    fn mul(self, rhs: N) -> Self::Output {
        SymbolicVar::from(self) * rhs
    }
}

impl<F: Field> Mul for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn mul(self, rhs: Self) -> Self::Output {
        SymbolicFelt::<F>::from(self) * rhs
    }
}

impl<F: Field> Mul<F> for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn mul(self, rhs: F) -> Self::Output {
        SymbolicFelt::from(self) * rhs
    }
}

impl<N: Field> Sub for Var<N> {
    type Output = SymbolicVar<N>;

    fn sub(self, rhs: Self) -> Self::Output {
        SymbolicVar::<N>::from(self) - rhs
    }
}

impl<N: Field> Sub<N> for Var<N> {
    type Output = SymbolicVar<N>;

    fn sub(self, rhs: N) -> Self::Output {
        SymbolicVar::from(self) - rhs
    }
}

impl<F: Field> Sub for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn sub(self, rhs: Self) -> Self::Output {
        SymbolicFelt::<F>::from(self) - rhs
    }
}

impl<F: Field> Sub<F> for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn sub(self, rhs: F) -> Self::Output {
        SymbolicFelt::from(self) - rhs
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Add<E> for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn add(self, rhs: E) -> Self::Output {
        let rhs: ExtOperand<F, EF> = rhs.to_operand();
        let self_sym = self.to_operand().symbolic();
        self_sym + rhs
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Mul<E> for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn mul(self, rhs: E) -> Self::Output {
        let self_sym = self.to_operand().symbolic();
        self_sym * rhs
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Sub<E> for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn sub(self, rhs: E) -> Self::Output {
        let self_sym = self.to_operand().symbolic();
        self_sym - rhs
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Div<E> for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn div(self, rhs: E) -> Self::Output {
        let self_sym = self.to_operand().symbolic();
        self_sym / rhs
    }
}

impl<F: Field, EF: ExtensionField<F>> Add<SymbolicExt<F, EF>> for Felt<F> {
    type Output = SymbolicExt<F, EF>;

    fn add(self, rhs: SymbolicExt<F, EF>) -> Self::Output {
        let self_sym = self.to_operand().symbolic();
        self_sym + rhs
    }
}

impl<F: Field, EF: ExtensionField<F>> Mul<SymbolicExt<F, EF>> for Felt<F> {
    type Output = SymbolicExt<F, EF>;

    fn mul(self, rhs: SymbolicExt<F, EF>) -> Self::Output {
        let self_sym = self.to_operand().symbolic();
        self_sym * rhs
    }
}

impl<F: Field, EF: ExtensionField<F>> Sub<SymbolicExt<F, EF>> for Felt<F> {
    type Output = SymbolicExt<F, EF>;

    fn sub(self, rhs: SymbolicExt<F, EF>) -> Self::Output {
        let self_sym = self.to_operand().symbolic();
        self_sym - rhs
    }
}

impl<F: Field, EF: ExtensionField<F>> Div<SymbolicExt<F, EF>> for Felt<F> {
    type Output = SymbolicExt<F, EF>;

    fn div(self, rhs: SymbolicExt<F, EF>) -> Self::Output {
        let self_sym = self.to_operand().symbolic();
        self_sym / rhs
    }
}

impl<F: Field> Div for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn div(self, rhs: Self) -> Self::Output {
        SymbolicFelt::<F>::from(self) / rhs
    }
}

impl<F: Field> Div<F> for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn div(self, rhs: F) -> Self::Output {
        SymbolicFelt::from(self) / rhs
    }
}

impl<F: Field> Div<Felt<F>> for SymbolicFelt<F> {
    type Output = SymbolicFelt<F>;

    fn div(self, rhs: Felt<F>) -> Self::Output {
        self / SymbolicFelt::from(rhs)
    }
}

impl<F: Field> Div<F> for SymbolicFelt<F> {
    type Output = SymbolicFelt<F>;

    fn div(self, rhs: F) -> Self::Output {
        self / SymbolicFelt::from(rhs)
    }
}

impl<N: Field> Sub<SymbolicVar<N>> for Var<N> {
    type Output = SymbolicVar<N>;

    fn sub(self, rhs: SymbolicVar<N>) -> Self::Output {
        SymbolicVar::<N>::from(self) - rhs
    }
}

impl<N: Field> Add<SymbolicVar<N>> for Var<N> {
    type Output = SymbolicVar<N>;

    fn add(self, rhs: SymbolicVar<N>) -> Self::Output {
        SymbolicVar::<N>::from(self) + rhs
    }
}

impl<N: Field> Mul<usize> for Usize<N> {
    type Output = SymbolicVar<N>;

    fn mul(self, rhs: usize) -> Self::Output {
        match self {
            Usize::Const(n) => SymbolicVar::from(N::from_canonical_usize(n * rhs)),
            Usize::Var(n) => SymbolicVar::from(n) * N::from_canonical_usize(rhs),
        }
    }
}

impl<N: Field> Product for SymbolicVar<N> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(SymbolicVar::one(), |acc, x| acc * x)
    }
}

impl<N: Field> Sum for SymbolicVar<N> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(SymbolicVar::zero(), |acc, x| acc + x)
    }
}

impl<N: Field> AddAssign for SymbolicVar<N> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<N: Field> SubAssign for SymbolicVar<N> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<N: Field> MulAssign for SymbolicVar<N> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<N: Field> Default for SymbolicVar<N> {
    fn default() -> Self {
        SymbolicVar::zero()
    }
}

impl<F: Field> Sum for SymbolicFelt<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(SymbolicFelt::zero(), |acc, x| acc + x)
    }
}

impl<F: Field> Product for SymbolicFelt<F> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(SymbolicFelt::one(), |acc, x| acc * x)
    }
}

impl<F: Field> AddAssign for SymbolicFelt<F> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<F: Field> SubAssign for SymbolicFelt<F> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<F: Field> MulAssign for SymbolicFelt<F> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<F: Field> Default for SymbolicFelt<F> {
    fn default() -> Self {
        SymbolicFelt::zero()
    }
}

impl<F: Field, EF: ExtensionField<F>> Sum for SymbolicExt<F, EF> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(SymbolicExt::zero(), |acc, x| acc + x)
    }
}

impl<F: Field, EF: ExtensionField<F>> Product for SymbolicExt<F, EF> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(SymbolicExt::one(), |acc, x| acc * x)
    }
}

impl<F: Field, EF: ExtensionField<F>> Default for SymbolicExt<F, EF> {
    fn default() -> Self {
        SymbolicExt::zero()
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> AddAssign<E> for SymbolicExt<F, EF> {
    fn add_assign(&mut self, rhs: E) {
        *self = *self + rhs;
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> SubAssign<E> for SymbolicExt<F, EF> {
    fn sub_assign(&mut self, rhs: E) {
        *self = *self - rhs;
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> MulAssign<E> for SymbolicExt<F, EF> {
    fn mul_assign(&mut self, rhs: E) {
        *self = *self * rhs;
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> DivAssign<E> for SymbolicExt<F, EF> {
    fn div_assign(&mut self, rhs: E) {
        *self = *self / rhs;
    }
}

impl<F: Field, EF: ExtensionField<F>> Mul<SymbolicExt<F, EF>> for SymbolicFelt<F> {
    type Output = SymbolicExt<F, EF>;

    fn mul(self, rhs: SymbolicExt<F, EF>) -> Self::Output {
        rhs * self
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> ExtensionOperand<F, EF> for E {
    fn to_operand(self) -> ExtOperand<F, EF> {
        match self.type_id() {
            ty if ty == TypeId::of::<F>() => {
                // *Safety*: We know that E is a F and we can transmute it to F which implements
                // the Copy trait.
                let value = unsafe { mem::transmute_copy::<E, F>(&self) };
                ExtOperand::<F, EF>::Base(value)
            }
            ty if ty == TypeId::of::<EF>() => {
                // *Safety*: We know that E is a EF and we can transmute it to EF which implements
                // the Copy trait.
                let value = unsafe { mem::transmute_copy::<E, EF>(&self) };
                ExtOperand::<F, EF>::Const(value)
            }
            ty if ty == TypeId::of::<Felt<F>>() => {
                // *Safety*: We know that E is a Felt<F> and we can transmute it to Felt<F> which
                // implements the Copy trait.
                let value = unsafe { mem::transmute_copy::<E, Felt<F>>(&self) };
                ExtOperand::<F, EF>::Felt(value)
            }
            ty if ty == TypeId::of::<Ext<F, EF>>() => {
                // *Safety*: We know that E is a Ext<F, EF> and we can transmute it to Ext<F, EF>
                // which implements the Copy trait.
                let value = unsafe { mem::transmute_copy::<E, Ext<F, EF>>(&self) };
                ExtOperand::<F, EF>::Ext(value)
            }
            ty if ty == TypeId::of::<SymbolicFelt<F>>() => {
                // *Safety*: We know that E is a Symbolic Felt<F> and we can transmute it to
                // SymbolicFelt<F> but we need to clone the pointer.
                let value_ref = unsafe { mem::transmute::<&E, &SymbolicFelt<F>>(&self) };
                let value = *value_ref;
                ExtOperand::<F, EF>::SymFelt(value)
            }
            ty if ty == TypeId::of::<SymbolicExt<F, EF>>() => {
                // *Safety*: We know that E is a SymbolicExt<F, EF> and we can transmute it to
                // SymbolicExt<F, EF> but we need to clone the pointer.
                let value_ref = unsafe { mem::transmute::<&E, &SymbolicExt<F, EF>>(&self) };
                let value = *value_ref;
                ExtOperand::<F, EF>::Sym(value)
            }
            ty if ty == TypeId::of::<ExtOperand<F, EF>>() => {
                let value_ref = unsafe { mem::transmute::<&E, &ExtOperand<F, EF>>(&self) };
                value_ref.clone()
            }
            _ => unimplemented!("unsupported type"),
        }
    }
}

impl<F: Field> Add<SymbolicFelt<F>> for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn add(self, rhs: SymbolicFelt<F>) -> Self::Output {
        SymbolicFelt::<F>::from(self) + rhs
    }
}

impl<F: Field, EF: ExtensionField<F>> From<Felt<F>> for SymbolicExt<F, EF> {
    fn from(value: Felt<F>) -> Self {
        value.to_operand().symbolic()
    }
}

impl<F: Field, EF: ExtensionField<F>> Neg for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;
    fn neg(self) -> Self::Output {
        -SymbolicExt::from(self)
    }
}

impl<F: Field> Neg for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn neg(self) -> Self::Output {
        -SymbolicFelt::from(self)
    }
}

impl<N: Field> Neg for Var<N> {
    type Output = SymbolicVar<N>;

    fn neg(self) -> Self::Output {
        -SymbolicVar::from(self)
    }
}

impl<N: Field> From<usize> for SymbolicUsize<N> {
    fn from(n: usize) -> Self {
        SymbolicUsize::Const(n)
    }
}

impl<N: Field> From<SymbolicVar<N>> for SymbolicUsize<N> {
    fn from(n: SymbolicVar<N>) -> Self {
        SymbolicUsize::Var(n)
    }
}

impl<N: Field> From<Var<N>> for SymbolicUsize<N> {
    fn from(n: Var<N>) -> Self {
        SymbolicUsize::Var(SymbolicVar::from(n))
    }
}

impl<N: Field> Add for SymbolicUsize<N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (SymbolicUsize::Const(a), SymbolicUsize::Const(b)) => SymbolicUsize::Const(a + b),
            (SymbolicUsize::Var(a), SymbolicUsize::Const(b)) => {
                SymbolicUsize::Var(a + N::from_canonical_usize(b))
            }
            (SymbolicUsize::Const(a), SymbolicUsize::Var(b)) => {
                SymbolicUsize::Var(b + N::from_canonical_usize(a))
            }
            (SymbolicUsize::Var(a), SymbolicUsize::Var(b)) => SymbolicUsize::Var(a + b),
        }
    }
}

impl<N: Field> Sub for SymbolicUsize<N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (SymbolicUsize::Const(a), SymbolicUsize::Const(b)) => SymbolicUsize::Const(a - b),
            (SymbolicUsize::Var(a), SymbolicUsize::Const(b)) => {
                SymbolicUsize::Var(a - N::from_canonical_usize(b))
            }
            (SymbolicUsize::Const(a), SymbolicUsize::Var(b)) => {
                SymbolicUsize::Var(SymbolicVar::from(N::from_canonical_usize(a)) - b)
            }
            (SymbolicUsize::Var(a), SymbolicUsize::Var(b)) => SymbolicUsize::Var(a - b),
        }
    }
}

impl<N: Field> Add<usize> for SymbolicUsize<N> {
    type Output = Self;

    fn add(self, rhs: usize) -> Self::Output {
        match self {
            SymbolicUsize::Const(a) => SymbolicUsize::Const(a + rhs),
            SymbolicUsize::Var(a) => SymbolicUsize::Var(a + N::from_canonical_usize(rhs)),
        }
    }
}

impl<N: Field> Sub<usize> for SymbolicUsize<N> {
    type Output = Self;

    fn sub(self, rhs: usize) -> Self::Output {
        match self {
            SymbolicUsize::Const(a) => SymbolicUsize::Const(a - rhs),
            SymbolicUsize::Var(a) => SymbolicUsize::Var(a - N::from_canonical_usize(rhs)),
        }
    }
}

impl<N: Field> From<Usize<N>> for SymbolicUsize<N> {
    fn from(n: Usize<N>) -> Self {
        match n {
            Usize::Const(n) => SymbolicUsize::Const(n),
            Usize::Var(n) => SymbolicUsize::Var(SymbolicVar::from(n)),
        }
    }
}

impl<N: Field> Add<Usize<N>> for SymbolicUsize<N> {
    type Output = SymbolicUsize<N>;

    fn add(self, rhs: Usize<N>) -> Self::Output {
        self + Self::from(rhs)
    }
}

impl<N: Field> Sub<Usize<N>> for SymbolicUsize<N> {
    type Output = SymbolicUsize<N>;

    fn sub(self, rhs: Usize<N>) -> Self::Output {
        self - Self::from(rhs)
    }
}

impl<N: Field> Add<usize> for Usize<N> {
    type Output = SymbolicUsize<N>;

    fn add(self, rhs: usize) -> Self::Output {
        SymbolicUsize::from(self) + rhs
    }
}

impl<N: Field> Sub<usize> for Usize<N> {
    type Output = SymbolicUsize<N>;

    fn sub(self, rhs: usize) -> Self::Output {
        SymbolicUsize::from(self) - rhs
    }
}

impl<N: Field> Add<Usize<N>> for Usize<N> {
    type Output = SymbolicUsize<N>;

    fn add(self, rhs: Usize<N>) -> Self::Output {
        SymbolicUsize::from(self) + rhs
    }
}

impl<N: Field> Sub<Usize<N>> for Usize<N> {
    type Output = SymbolicUsize<N>;

    fn sub(self, rhs: Usize<N>) -> Self::Output {
        SymbolicUsize::from(self) - rhs
    }
}

impl<F: Field> MulAssign<Felt<F>> for SymbolicFelt<F> {
    fn mul_assign(&mut self, rhs: Felt<F>) {
        *self = *self * Self::from(rhs);
    }
}

impl<F: Field> Mul<SymbolicFelt<F>> for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn mul(self, rhs: SymbolicFelt<F>) -> Self::Output {
        SymbolicFelt::<F>::from(self) * rhs
    }
}

impl<N: Field> Mul<SymbolicVar<N>> for Var<N> {
    type Output = SymbolicVar<N>;

    fn mul(self, rhs: SymbolicVar<N>) -> Self::Output {
        SymbolicVar::<N>::from(self) * rhs
    }
}

impl<N: Field> Sub<Usize<N>> for SymbolicVar<N> {
    type Output = SymbolicVar<N>;

    fn sub(self, rhs: Usize<N>) -> Self::Output {
        match rhs {
            Usize::Const(n) => self - N::from_canonical_usize(n),
            Usize::Var(n) => self - n,
        }
    }
}

impl<N: Field> Add<Usize<N>> for SymbolicVar<N> {
    type Output = SymbolicVar<N>;

    fn add(self, rhs: Usize<N>) -> Self::Output {
        match rhs {
            Usize::Const(n) => self + N::from_canonical_usize(n),
            Usize::Var(n) => self + n,
        }
    }
}

impl<N: Field> Add<Usize<N>> for Var<N> {
    type Output = SymbolicVar<N>;

    fn add(self, rhs: Usize<N>) -> Self::Output {
        SymbolicVar::<N>::from(self) + rhs
    }
}

impl<N: Field> Sub<Usize<N>> for Var<N> {
    type Output = SymbolicVar<N>;

    fn sub(self, rhs: Usize<N>) -> Self::Output {
        SymbolicVar::<N>::from(self) - rhs
    }
}

impl<N: Field> Sub<SymbolicVar<N>> for Usize<N> {
    type Output = SymbolicVar<N>;

    fn sub(self, rhs: SymbolicVar<N>) -> Self::Output {
        match self {
            Usize::Const(n) => SymbolicVar::from(N::from_canonical_usize(n)) - rhs,
            Usize::Var(n) => SymbolicVar::<N>::from(n) - rhs,
        }
    }
}

impl<N: Field> Add<SymbolicVar<N>> for Usize<N> {
    type Output = SymbolicVar<N>;

    fn add(self, rhs: SymbolicVar<N>) -> Self::Output {
        match self {
            Usize::Const(n) => SymbolicVar::from(N::from_canonical_usize(n)) + rhs,
            Usize::Var(n) => SymbolicVar::<N>::from(n) + rhs,
        }
    }
}

impl<N: Field> Add<Var<N>> for Usize<N> {
    type Output = SymbolicVar<N>;

    fn add(self, rhs: Var<N>) -> Self::Output {
        self + SymbolicVar::<N>::from(rhs)
    }
}

impl<N: Field> Sub<Var<N>> for Usize<N> {
    type Output = SymbolicVar<N>;

    fn sub(self, rhs: Var<N>) -> Self::Output {
        self - SymbolicVar::<N>::from(rhs)
    }
}

impl<N: Field> From<Usize<N>> for SymbolicVar<N> {
    fn from(value: Usize<N>) -> Self {
        match value {
            Usize::Const(n) => SymbolicVar::from(N::from_canonical_usize(n)),
            Usize::Var(n) => SymbolicVar::from(n),
        }
    }
}
