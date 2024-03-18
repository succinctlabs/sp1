use super::Usize;
use super::{Ext, Felt, Var};
use alloc::rc::Rc;
use core::any::Any;
use core::ops::{Add, Div, Mul, Neg, Sub};
use p3_field::Field;
use p3_field::{AbstractField, ExtensionField};
use std::any::TypeId;
use std::iter::{Product, Sum};
use std::mem;
use std::ops::{AddAssign, DivAssign, MulAssign, SubAssign};

#[derive(Debug, Clone)]
pub enum SymbolicVar<N> {
    Const(N),
    Val(Var<N>),
    Add(Rc<SymbolicVar<N>>, Rc<SymbolicVar<N>>),
    Mul(Rc<SymbolicVar<N>>, Rc<SymbolicVar<N>>),
    Sub(Rc<SymbolicVar<N>>, Rc<SymbolicVar<N>>),
    Neg(Rc<SymbolicVar<N>>),
}

#[derive(Debug, Clone)]
pub enum SymbolicFelt<F> {
    Const(F),
    Val(Felt<F>),
    Add(Rc<SymbolicFelt<F>>, Rc<SymbolicFelt<F>>),
    Mul(Rc<SymbolicFelt<F>>, Rc<SymbolicFelt<F>>),
    Sub(Rc<SymbolicFelt<F>>, Rc<SymbolicFelt<F>>),
    Div(Rc<SymbolicFelt<F>>, Rc<SymbolicFelt<F>>),
    Neg(Rc<SymbolicFelt<F>>),
}

#[derive(Debug, Clone)]
pub enum SymbolicExt<F, EF> {
    Const(EF),
    Base(Rc<SymbolicFelt<F>>),
    Val(Ext<F, EF>),
    Add(Rc<SymbolicExt<F, EF>>, Rc<SymbolicExt<F, EF>>),
    Mul(Rc<SymbolicExt<F, EF>>, Rc<SymbolicExt<F, EF>>),
    Sub(Rc<SymbolicExt<F, EF>>, Rc<SymbolicExt<F, EF>>),
    Div(Rc<SymbolicExt<F, EF>>, Rc<SymbolicExt<F, EF>>),
    Neg(Rc<SymbolicExt<F, EF>>),
}

#[derive(Debug, Clone)]
pub enum ExtOperand<F, EF> {
    Base(F),
    Const(EF),
    Felt(Felt<F>),
    Ext(Ext<F, EF>),
    SymFelt(SymbolicFelt<F>),
    Sym(SymbolicExt<F, EF>),
}

pub trait ExtConst<F: Field, EF: ExtensionField<F>> {
    fn cons(self) -> SymbolicExt<F, EF>;
}

impl<F: Field, EF: ExtensionField<F>> ExtConst<F, EF> for EF {
    fn cons(self) -> SymbolicExt<F, EF> {
        SymbolicExt::Const(self)
    }
}

pub trait ExtensionOperand<F: Field, EF: ExtensionField<EF>> {
    fn to_operand(self) -> ExtOperand<F, EF>;
}

impl<N: Field> AbstractField for SymbolicVar<N> {
    type F = N;

    fn zero() -> Self {
        SymbolicVar::Const(N::zero())
    }

    fn one() -> Self {
        SymbolicVar::Const(N::one())
    }

    fn two() -> Self {
        SymbolicVar::Const(N::two())
    }

    fn neg_one() -> Self {
        SymbolicVar::Const(N::neg_one())
    }

    fn from_f(f: Self::F) -> Self {
        SymbolicVar::Const(f)
    }
    fn from_bool(b: bool) -> Self {
        SymbolicVar::Const(N::from_bool(b))
    }
    fn from_canonical_u8(n: u8) -> Self {
        SymbolicVar::Const(N::from_canonical_u8(n))
    }
    fn from_canonical_u16(n: u16) -> Self {
        SymbolicVar::Const(N::from_canonical_u16(n))
    }
    fn from_canonical_u32(n: u32) -> Self {
        SymbolicVar::Const(N::from_canonical_u32(n))
    }
    fn from_canonical_u64(n: u64) -> Self {
        SymbolicVar::Const(N::from_canonical_u64(n))
    }
    fn from_canonical_usize(n: usize) -> Self {
        SymbolicVar::Const(N::from_canonical_usize(n))
    }

    fn from_wrapped_u32(n: u32) -> Self {
        SymbolicVar::Const(N::from_wrapped_u32(n))
    }
    fn from_wrapped_u64(n: u64) -> Self {
        SymbolicVar::Const(N::from_wrapped_u64(n))
    }

    /// A generator of this field's entire multiplicative group.
    fn generator() -> Self {
        SymbolicVar::Const(N::generator())
    }
}

impl<F: Field> AbstractField for SymbolicFelt<F> {
    type F = F;

    fn zero() -> Self {
        SymbolicFelt::Const(F::zero())
    }

    fn one() -> Self {
        SymbolicFelt::Const(F::one())
    }

    fn two() -> Self {
        SymbolicFelt::Const(F::two())
    }

    fn neg_one() -> Self {
        SymbolicFelt::Const(F::neg_one())
    }

    fn from_f(f: Self::F) -> Self {
        SymbolicFelt::Const(f)
    }
    fn from_bool(b: bool) -> Self {
        SymbolicFelt::Const(F::from_bool(b))
    }
    fn from_canonical_u8(n: u8) -> Self {
        SymbolicFelt::Const(F::from_canonical_u8(n))
    }
    fn from_canonical_u16(n: u16) -> Self {
        SymbolicFelt::Const(F::from_canonical_u16(n))
    }
    fn from_canonical_u32(n: u32) -> Self {
        SymbolicFelt::Const(F::from_canonical_u32(n))
    }
    fn from_canonical_u64(n: u64) -> Self {
        SymbolicFelt::Const(F::from_canonical_u64(n))
    }
    fn from_canonical_usize(n: usize) -> Self {
        SymbolicFelt::Const(F::from_canonical_usize(n))
    }

    fn from_wrapped_u32(n: u32) -> Self {
        SymbolicFelt::Const(F::from_wrapped_u32(n))
    }
    fn from_wrapped_u64(n: u64) -> Self {
        SymbolicFelt::Const(F::from_wrapped_u64(n))
    }

    /// A generator of this field's entire multiplicative group.
    fn generator() -> Self {
        SymbolicFelt::Const(F::generator())
    }
}

impl<F: Field, EF: ExtensionField<F>> AbstractField for SymbolicExt<F, EF> {
    type F = EF;

    fn zero() -> Self {
        SymbolicExt::Const(EF::zero())
    }

    fn one() -> Self {
        SymbolicExt::Const(EF::one())
    }

    fn two() -> Self {
        SymbolicExt::Const(EF::two())
    }

    fn neg_one() -> Self {
        SymbolicExt::Const(EF::neg_one())
    }

    fn from_f(f: Self::F) -> Self {
        SymbolicExt::Const(f)
    }
    fn from_bool(b: bool) -> Self {
        SymbolicExt::Const(EF::from_bool(b))
    }
    fn from_canonical_u8(n: u8) -> Self {
        SymbolicExt::Const(EF::from_canonical_u8(n))
    }
    fn from_canonical_u16(n: u16) -> Self {
        SymbolicExt::Const(EF::from_canonical_u16(n))
    }
    fn from_canonical_u32(n: u32) -> Self {
        SymbolicExt::Const(EF::from_canonical_u32(n))
    }
    fn from_canonical_u64(n: u64) -> Self {
        SymbolicExt::Const(EF::from_canonical_u64(n))
    }
    fn from_canonical_usize(n: usize) -> Self {
        SymbolicExt::Const(EF::from_canonical_usize(n))
    }

    fn from_wrapped_u32(n: u32) -> Self {
        SymbolicExt::Const(EF::from_wrapped_u32(n))
    }
    fn from_wrapped_u64(n: u64) -> Self {
        SymbolicExt::Const(EF::from_wrapped_u64(n))
    }

    /// A generator of this field's entire multiplicative group.
    fn generator() -> Self {
        SymbolicExt::Const(EF::generator())
    }
}

// Implement all conversions from constants N, F, EF, to the corresponding symbolic types

impl<N> From<N> for SymbolicVar<N> {
    fn from(n: N) -> Self {
        SymbolicVar::Const(n)
    }
}

impl<F> From<F> for SymbolicFelt<F> {
    fn from(f: F) -> Self {
        SymbolicFelt::Const(f)
    }
}

impl<F: Field, EF: ExtensionField<F>> From<F> for SymbolicExt<F, EF> {
    fn from(f: F) -> Self {
        SymbolicExt::Base(Rc::new(SymbolicFelt::Const(f)))
    }
}

// Implement all conversions from Var<N>, Felt<F>, Ext<F, EF> to the corresponding symbolic types

impl<N> From<Var<N>> for SymbolicVar<N> {
    fn from(v: Var<N>) -> Self {
        SymbolicVar::Val(v)
    }
}

impl<F> From<Felt<F>> for SymbolicFelt<F> {
    fn from(f: Felt<F>) -> Self {
        SymbolicFelt::Val(f)
    }
}

impl<F: Field, EF: ExtensionField<F>> From<Ext<F, EF>> for SymbolicExt<F, EF> {
    fn from(e: Ext<F, EF>) -> Self {
        SymbolicExt::Val(e)
    }
}

// Implement all operations for SymbolicVar<N>, SymbolicFelt<F>, SymbolicExt<F, EF>

impl<N> Add for SymbolicVar<N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        SymbolicVar::Add(Rc::new(self), Rc::new(rhs))
    }
}

impl<F> Add for SymbolicFelt<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        SymbolicFelt::Add(Rc::new(self), Rc::new(rhs))
    }
}

impl<F: Field, EF: ExtensionField<F>, E: ExtensionOperand<F, EF>> Add<E> for SymbolicExt<F, EF> {
    type Output = Self;

    fn add(self, rhs: E) -> Self::Output {
        let rhs = rhs.to_operand();
        match rhs {
            ExtOperand::Base(f) => SymbolicExt::Add(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::Const(f)))),
            ),
            ExtOperand::Const(ef) => {
                SymbolicExt::Add(Rc::new(self), Rc::new(SymbolicExt::Const(ef)))
            }
            ExtOperand::Felt(f) => SymbolicExt::Add(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::Val(f)))),
            ),
            ExtOperand::Ext(e) => SymbolicExt::Add(Rc::new(self), Rc::new(SymbolicExt::Val(e))),
            ExtOperand::SymFelt(f) => {
                SymbolicExt::Add(Rc::new(self), Rc::new(SymbolicExt::Base(Rc::new(f))))
            }
            ExtOperand::Sym(e) => SymbolicExt::Add(Rc::new(self), Rc::new(e)),
        }
    }
}

impl<N> Mul for SymbolicVar<N> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        SymbolicVar::Mul(Rc::new(self), Rc::new(rhs))
    }
}

impl<F> Mul for SymbolicFelt<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        SymbolicFelt::Mul(Rc::new(self), Rc::new(rhs))
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Mul<E> for SymbolicExt<F, EF> {
    type Output = Self;

    fn mul(self, rhs: E) -> Self::Output {
        let rhs = rhs.to_operand();
        match rhs {
            ExtOperand::Base(f) => SymbolicExt::Mul(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::Const(f)))),
            ),
            ExtOperand::Const(ef) => {
                SymbolicExt::Mul(Rc::new(self), Rc::new(SymbolicExt::Const(ef)))
            }
            ExtOperand::Felt(f) => SymbolicExt::Mul(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::Val(f)))),
            ),
            ExtOperand::Ext(e) => SymbolicExt::Mul(Rc::new(self), Rc::new(SymbolicExt::Val(e))),
            ExtOperand::SymFelt(f) => {
                SymbolicExt::Mul(Rc::new(self), Rc::new(SymbolicExt::Base(Rc::new(f))))
            }
            ExtOperand::Sym(e) => SymbolicExt::Mul(Rc::new(self), Rc::new(e)),
        }
    }
}

impl<N> Sub for SymbolicVar<N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        SymbolicVar::Sub(Rc::new(self), Rc::new(rhs))
    }
}

impl<F> Sub for SymbolicFelt<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        SymbolicFelt::Sub(Rc::new(self), Rc::new(rhs))
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Sub<E> for SymbolicExt<F, EF> {
    type Output = Self;

    fn sub(self, rhs: E) -> Self::Output {
        let rhs = rhs.to_operand();
        match rhs {
            ExtOperand::Base(f) => SymbolicExt::Sub(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::Const(f)))),
            ),
            ExtOperand::Const(ef) => {
                SymbolicExt::Sub(Rc::new(self), Rc::new(SymbolicExt::Const(ef)))
            }
            ExtOperand::Felt(f) => SymbolicExt::Sub(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::Val(f)))),
            ),
            ExtOperand::Ext(e) => SymbolicExt::Sub(Rc::new(self), Rc::new(SymbolicExt::Val(e))),
            ExtOperand::SymFelt(f) => {
                SymbolicExt::Sub(Rc::new(self), Rc::new(SymbolicExt::Base(Rc::new(f))))
            }
            ExtOperand::Sym(e) => SymbolicExt::Sub(Rc::new(self), Rc::new(e)),
        }
    }
}

impl<F> Div for SymbolicFelt<F> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        SymbolicFelt::Div(Rc::new(self), Rc::new(rhs))
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Div<E> for SymbolicExt<F, EF> {
    type Output = Self;

    fn div(self, rhs: E) -> Self::Output {
        let rhs = rhs.to_operand();
        match rhs {
            ExtOperand::Base(f) => SymbolicExt::Div(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::Const(f)))),
            ),
            ExtOperand::Const(ef) => {
                SymbolicExt::Div(Rc::new(self), Rc::new(SymbolicExt::Const(ef)))
            }
            ExtOperand::Felt(f) => SymbolicExt::Div(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::Val(f)))),
            ),
            ExtOperand::Ext(e) => SymbolicExt::Div(Rc::new(self), Rc::new(SymbolicExt::Val(e))),
            ExtOperand::SymFelt(f) => {
                SymbolicExt::Div(Rc::new(self), Rc::new(SymbolicExt::Base(Rc::new(f))))
            }
            ExtOperand::Sym(e) => SymbolicExt::Div(Rc::new(self), Rc::new(e)),
        }
    }
}

impl<N> Neg for SymbolicVar<N> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        SymbolicVar::Neg(Rc::new(self))
    }
}

impl<F> Neg for SymbolicFelt<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        SymbolicFelt::Neg(Rc::new(self))
    }
}

impl<F: Field, EF: ExtensionField<F>> Neg for SymbolicExt<F, EF> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        SymbolicExt::Neg(Rc::new(self))
    }
}

// Implement all operations between N, F, EF, and SymbolicVar<N>, SymbolicFelt<F>, SymbolicExt<F, EF>

impl<N> Add<N> for SymbolicVar<N> {
    type Output = Self;

    fn add(self, rhs: N) -> Self::Output {
        SymbolicVar::Add(Rc::new(self), Rc::new(SymbolicVar::Const(rhs)))
    }
}

impl<F> Add<F> for SymbolicFelt<F> {
    type Output = Self;

    fn add(self, rhs: F) -> Self::Output {
        SymbolicFelt::Add(Rc::new(self), Rc::new(SymbolicFelt::Const(rhs)))
    }
}

impl<N> Mul<N> for SymbolicVar<N> {
    type Output = Self;

    fn mul(self, rhs: N) -> Self::Output {
        SymbolicVar::Mul(Rc::new(self), Rc::new(SymbolicVar::Const(rhs)))
    }
}

impl<F> Mul<F> for SymbolicFelt<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        SymbolicFelt::Mul(Rc::new(self), Rc::new(SymbolicFelt::Const(rhs)))
    }
}

impl<N> Sub<N> for SymbolicVar<N> {
    type Output = Self;

    fn sub(self, rhs: N) -> Self::Output {
        SymbolicVar::Sub(Rc::new(self), Rc::new(SymbolicVar::Const(rhs)))
    }
}

impl<F> Sub<F> for SymbolicFelt<F> {
    type Output = Self;

    fn sub(self, rhs: F) -> Self::Output {
        SymbolicFelt::Sub(Rc::new(self), Rc::new(SymbolicFelt::Const(rhs)))
    }
}

// Implement all operations between SymbolicVar<N>, SymbolicFelt<F>, SymbolicExt<F, EF>, and Var<N>,
//  Felt<F>, Ext<F, EF>.

impl<N> Add<Var<N>> for SymbolicVar<N> {
    type Output = SymbolicVar<N>;

    fn add(self, rhs: Var<N>) -> Self::Output {
        self + SymbolicVar::from(rhs)
    }
}

impl<F> Add<Felt<F>> for SymbolicFelt<F> {
    type Output = SymbolicFelt<F>;

    fn add(self, rhs: Felt<F>) -> Self::Output {
        self + SymbolicFelt::from(rhs)
    }
}

impl<N> Mul<Var<N>> for SymbolicVar<N> {
    type Output = SymbolicVar<N>;

    fn mul(self, rhs: Var<N>) -> Self::Output {
        self * SymbolicVar::from(rhs)
    }
}

impl<F> Mul<Felt<F>> for SymbolicFelt<F> {
    type Output = SymbolicFelt<F>;

    fn mul(self, rhs: Felt<F>) -> Self::Output {
        self * SymbolicFelt::from(rhs)
    }
}

impl<N> Sub<Var<N>> for SymbolicVar<N> {
    type Output = SymbolicVar<N>;

    fn sub(self, rhs: Var<N>) -> Self::Output {
        self - SymbolicVar::from(rhs)
    }
}

impl<F> Sub<Felt<F>> for SymbolicFelt<F> {
    type Output = SymbolicFelt<F>;

    fn sub(self, rhs: Felt<F>) -> Self::Output {
        self - SymbolicFelt::from(rhs)
    }
}

impl<F> Div<SymbolicFelt<F>> for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn div(self, rhs: SymbolicFelt<F>) -> Self::Output {
        SymbolicFelt::<F>::from(self) / rhs
    }
}

// Implement operations between constants N, F, EF, and Var<N>, Felt<F>, Ext<F, EF>.

impl<N> Add for Var<N> {
    type Output = SymbolicVar<N>;

    fn add(self, rhs: Self) -> Self::Output {
        SymbolicVar::<N>::from(self) + rhs
    }
}

impl<N> Add<N> for Var<N> {
    type Output = SymbolicVar<N>;

    fn add(self, rhs: N) -> Self::Output {
        SymbolicVar::from(self) + rhs
    }
}

impl<F> Add for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn add(self, rhs: Self) -> Self::Output {
        SymbolicFelt::<F>::from(self) + rhs
    }
}

impl<F> Add<F> for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn add(self, rhs: F) -> Self::Output {
        SymbolicFelt::from(self) + rhs
    }
}

impl<N> Mul for Var<N> {
    type Output = SymbolicVar<N>;

    fn mul(self, rhs: Self) -> Self::Output {
        SymbolicVar::<N>::from(self) * rhs
    }
}

impl<N> Mul<N> for Var<N> {
    type Output = SymbolicVar<N>;

    fn mul(self, rhs: N) -> Self::Output {
        SymbolicVar::from(self) * rhs
    }
}

impl<F> Mul for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn mul(self, rhs: Self) -> Self::Output {
        SymbolicFelt::<F>::from(self) * rhs
    }
}

impl<F> Mul<F> for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn mul(self, rhs: F) -> Self::Output {
        SymbolicFelt::from(self) * rhs
    }
}

impl<N> Sub for Var<N> {
    type Output = SymbolicVar<N>;

    fn sub(self, rhs: Self) -> Self::Output {
        SymbolicVar::<N>::from(self) - rhs
    }
}

impl<N> Sub<N> for Var<N> {
    type Output = SymbolicVar<N>;

    fn sub(self, rhs: N) -> Self::Output {
        SymbolicVar::from(self) - rhs
    }
}

impl<F> Sub for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn sub(self, rhs: Self) -> Self::Output {
        SymbolicFelt::<F>::from(self) - rhs
    }
}

impl<F> Sub<F> for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn sub(self, rhs: F) -> Self::Output {
        SymbolicFelt::from(self) - rhs
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Add<E> for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn add(self, rhs: E) -> Self::Output {
        let rhs: ExtOperand<F, EF> = rhs.to_operand();
        match rhs {
            ExtOperand::Base(f) => SymbolicExt::Base(Rc::new(SymbolicFelt::Const(f))) + self,
            ExtOperand::Const(ef) => SymbolicExt::Const(ef) + self,
            ExtOperand::Felt(f) => SymbolicExt::Base(Rc::new(SymbolicFelt::Val(f))) + self,
            ExtOperand::Ext(e) => SymbolicExt::Val(e) + self,
            ExtOperand::SymFelt(f) => SymbolicExt::Base(Rc::new(f)) + self,
            ExtOperand::Sym(e) => e + self,
        }
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Mul<E> for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn mul(self, rhs: E) -> Self::Output {
        let rhs: ExtOperand<F, EF> = rhs.to_operand();
        match rhs {
            ExtOperand::Base(f) => SymbolicExt::Base(Rc::new(SymbolicFelt::Const(f))) * self,
            ExtOperand::Const(ef) => SymbolicExt::Const(ef) * self,
            ExtOperand::Felt(f) => SymbolicExt::Base(Rc::new(SymbolicFelt::Val(f))) * self,
            ExtOperand::Ext(e) => SymbolicExt::Val(e) * self,
            ExtOperand::SymFelt(f) => SymbolicExt::Base(Rc::new(f)) * self,
            ExtOperand::Sym(e) => e * self,
        }
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Sub<E> for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn sub(self, rhs: E) -> Self::Output {
        let rhs: ExtOperand<F, EF> = rhs.to_operand();
        match rhs {
            ExtOperand::Base(f) => SymbolicExt::Sub(
                Rc::new(SymbolicExt::Val(self)),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::Const(f)))),
            ),
            ExtOperand::Const(ef) => SymbolicExt::Sub(
                Rc::new(SymbolicExt::Val(self)),
                Rc::new(SymbolicExt::Const(ef)),
            ),
            ExtOperand::Felt(f) => SymbolicExt::Sub(
                Rc::new(SymbolicExt::Val(self)),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::Val(f)))),
            ),
            ExtOperand::Ext(e) => SymbolicExt::Sub(
                Rc::new(SymbolicExt::Val(self)),
                Rc::new(SymbolicExt::Val(e)),
            ),
            ExtOperand::SymFelt(f) => SymbolicExt::Sub(
                Rc::new(SymbolicExt::Val(self)),
                Rc::new(SymbolicExt::Base(Rc::new(f))),
            ),
            ExtOperand::Sym(e) => SymbolicExt::Sub(Rc::new(SymbolicExt::Val(self)), Rc::new(e)),
        }
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Div<E> for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn div(self, rhs: E) -> Self::Output {
        let rhs: ExtOperand<F, EF> = rhs.to_operand();
        match rhs {
            ExtOperand::Base(f) => SymbolicExt::Div(
                Rc::new(SymbolicExt::Val(self)),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::Const(f)))),
            ),
            ExtOperand::Const(ef) => SymbolicExt::Div(
                Rc::new(SymbolicExt::Val(self)),
                Rc::new(SymbolicExt::Const(ef)),
            ),
            ExtOperand::Felt(f) => SymbolicExt::Div(
                Rc::new(SymbolicExt::Val(self)),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::Val(f)))),
            ),
            ExtOperand::Ext(e) => SymbolicExt::Div(
                Rc::new(SymbolicExt::Val(self)),
                Rc::new(SymbolicExt::Val(e)),
            ),
            ExtOperand::SymFelt(f) => SymbolicExt::Div(
                Rc::new(SymbolicExt::Val(self)),
                Rc::new(SymbolicExt::Base(Rc::new(f))),
            ),
            ExtOperand::Sym(e) => SymbolicExt::Div(Rc::new(SymbolicExt::Val(self)), Rc::new(e)),
        }
    }
}

impl<F: Field, EF: ExtensionField<F>> Add<SymbolicExt<F, EF>> for Felt<F> {
    type Output = SymbolicExt<F, EF>;

    fn add(self, rhs: SymbolicExt<F, EF>) -> Self::Output {
        SymbolicExt::<F, EF>::Base(Rc::new(SymbolicFelt::Val(self))) + rhs
    }
}

impl<F: Field, EF: ExtensionField<F>> Mul<SymbolicExt<F, EF>> for Felt<F> {
    type Output = SymbolicExt<F, EF>;

    fn mul(self, rhs: SymbolicExt<F, EF>) -> Self::Output {
        SymbolicExt::<F, EF>::Base(Rc::new(SymbolicFelt::Val(self))) * rhs
    }
}

impl<F: Field, EF: ExtensionField<F>> Sub<SymbolicExt<F, EF>> for Felt<F> {
    type Output = SymbolicExt<F, EF>;

    fn sub(self, rhs: SymbolicExt<F, EF>) -> Self::Output {
        SymbolicExt::<F, EF>::Base(Rc::new(SymbolicFelt::Val(self))) - rhs
    }
}

impl<F: Field, EF: ExtensionField<F>> Div<SymbolicExt<F, EF>> for Felt<F> {
    type Output = SymbolicExt<F, EF>;

    fn div(self, rhs: SymbolicExt<F, EF>) -> Self::Output {
        SymbolicExt::<F, EF>::Base(Rc::new(SymbolicFelt::Val(self))) / rhs
    }
}

impl<F> Div for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn div(self, rhs: Self) -> Self::Output {
        SymbolicFelt::<F>::from(self) / rhs
    }
}

impl<F> Div<F> for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn div(self, rhs: F) -> Self::Output {
        SymbolicFelt::from(self) / rhs
    }
}

impl<F> Div<Felt<F>> for SymbolicFelt<F> {
    type Output = SymbolicFelt<F>;

    fn div(self, rhs: Felt<F>) -> Self::Output {
        SymbolicFelt::Div(Rc::new(self), Rc::new(SymbolicFelt::Val(rhs)))
    }
}

impl<F> Div<F> for SymbolicFelt<F> {
    type Output = SymbolicFelt<F>;

    fn div(self, rhs: F) -> Self::Output {
        SymbolicFelt::Div(Rc::new(self), Rc::new(SymbolicFelt::Const(rhs)))
    }
}

impl<N> Sub<SymbolicVar<N>> for Var<N> {
    type Output = SymbolicVar<N>;

    fn sub(self, rhs: SymbolicVar<N>) -> Self::Output {
        SymbolicVar::<N>::from(self) - rhs
    }
}

impl<N> Add<SymbolicVar<N>> for Var<N> {
    type Output = SymbolicVar<N>;

    fn add(self, rhs: SymbolicVar<N>) -> Self::Output {
        SymbolicVar::<N>::from(self) + rhs
    }
}

impl<N: Field> Mul<usize> for Usize<N> {
    type Output = SymbolicVar<N>;

    fn mul(self, rhs: usize) -> Self::Output {
        match self {
            Usize::Const(n) => SymbolicVar::Const(N::from_canonical_usize(n * rhs)),
            Usize::Var(n) => SymbolicVar::Val(n) * N::from_canonical_usize(rhs),
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
        *self = self.clone() + rhs;
    }
}

impl<N: Field> SubAssign for SymbolicVar<N> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs;
    }
}

impl<N: Field> MulAssign for SymbolicVar<N> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
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
        *self = self.clone() + rhs;
    }
}

impl<F: Field> SubAssign for SymbolicFelt<F> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs;
    }
}

impl<F: Field> MulAssign for SymbolicFelt<F> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
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
        *self = self.clone() + rhs;
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> SubAssign<E> for SymbolicExt<F, EF> {
    fn sub_assign(&mut self, rhs: E) {
        *self = self.clone() - rhs;
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> MulAssign<E> for SymbolicExt<F, EF> {
    fn mul_assign(&mut self, rhs: E) {
        *self = self.clone() * rhs;
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> DivAssign<E> for SymbolicExt<F, EF> {
    fn div_assign(&mut self, rhs: E) {
        *self = self.clone() / rhs;
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> ExtensionOperand<F, EF> for E {
    fn to_operand(self) -> ExtOperand<F, EF> {
        match self.type_id() {
            ty if ty == TypeId::of::<F>() => {
                // *Saftey*: We know that E is a F and we can transmute it to F which implements
                // the Copy trait.
                let value = unsafe { mem::transmute_copy::<E, F>(&self) };
                ExtOperand::<F, EF>::Base(value)
            }
            ty if ty == TypeId::of::<EF>() => {
                // *Saftey*: We know that E is a EF and we can transmute it to EF which implements
                // the Copy trait.
                let value = unsafe { mem::transmute_copy::<E, EF>(&self) };
                ExtOperand::<F, EF>::Const(value)
            }
            ty if ty == TypeId::of::<Felt<F>>() => {
                // *Saftey*: We know that E is a Felt<F> and we can transmute it to Felt<F> which
                // implements the Copy trait.
                let value = unsafe { mem::transmute_copy::<E, Felt<F>>(&self) };
                ExtOperand::<F, EF>::Felt(value)
            }
            ty if ty == TypeId::of::<Ext<F, EF>>() => {
                // *Saftey*: We know that E is a Ext<F, EF> and we can transmute it to Ext<F, EF>
                // which implements the Copy trait.
                let value = unsafe { mem::transmute_copy::<E, Ext<F, EF>>(&self) };
                ExtOperand::<F, EF>::Ext(value)
            }
            ty if ty == TypeId::of::<SymbolicFelt<F>>() => {
                // *Saftey*: We know that E is a Symbolic Felt<F> and we can transmute it to
                // SymbolicFelt<F> but we need to clone the pointer.
                let value_ref = unsafe { mem::transmute::<&E, &SymbolicFelt<F>>(&self) };
                let value = value_ref.clone();
                ExtOperand::<F, EF>::SymFelt(value)
            }
            ty if ty == TypeId::of::<SymbolicExt<F, EF>>() => {
                // *Saftey*: We know that E is a SymbolicExt<F, EF> and we can transmute it to
                // SymbolicExt<F, EF> but we need to clone the pointer.
                let value_ref = unsafe { mem::transmute::<&E, &SymbolicExt<F, EF>>(&self) };
                let value = value_ref.clone();
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

impl<F: Field> Div<F> for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn div(self, rhs: F) -> Self::Output {
        let lhs = SymbolicFelt::Val(self);
        let rhs = SymbolicFelt::Const(rhs);
        SymbolicFelt::Div(lhs.into(), rhs.into())
    }
}
