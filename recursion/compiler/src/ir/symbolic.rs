use super::{Ext, Felt, Var};
use alloc::rc::Rc;
use core::ops::{Add, Div, Mul, Neg, Sub};
use p3_field::{
    extension::{BinomialExtensionField, BinomiallyExtendable},
    AbstractExtensionField, AbstractField, Field,
};
use std::{
    iter::{Product, Sum},
    ops::{AddAssign, MulAssign, SubAssign},
};

pub const D: usize = 4;
pub type BinomialExtension<F> = BinomialExtensionField<F, D>;

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
pub enum SymbolicExt<F> {
    Const(BinomialExtension<F>),
    Base(Rc<SymbolicFelt<F>>),
    Val(Ext<F>),
    Add(Rc<SymbolicExt<F>>, Rc<SymbolicExt<F>>),
    Mul(Rc<SymbolicExt<F>>, Rc<SymbolicExt<F>>),
    Sub(Rc<SymbolicExt<F>>, Rc<SymbolicExt<F>>),
    Div(Rc<SymbolicExt<F>>, Rc<SymbolicExt<F>>),
    Neg(Rc<SymbolicExt<F>>),
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

impl<F> From<BinomialExtension<F>> for SymbolicExt<F> {
    fn from(ef: BinomialExtension<F>) -> Self {
        SymbolicExt::Const(ef)
    }
}

// Implement all conversions from Var<N>, Felt<F>, Ext<F> to the corresponding symbolic types

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

impl<F> From<Ext<F>> for SymbolicExt<F> {
    fn from(e: Ext<F>) -> Self {
        SymbolicExt::Val(e)
    }
}

// Implement all operations for SymbolicVar<N>, SymbolicFelt<F>, SymbolicExt<F>

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

impl<F> Add for SymbolicExt<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        SymbolicExt::Add(Rc::new(self), Rc::new(rhs))
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

impl<F> Mul for SymbolicExt<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        SymbolicExt::Mul(Rc::new(self), Rc::new(rhs))
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

impl<F> Sub for SymbolicExt<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        SymbolicExt::Sub(Rc::new(self), Rc::new(rhs))
    }
}

impl<F> Div for SymbolicFelt<F> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        SymbolicFelt::Div(Rc::new(self), Rc::new(rhs))
    }
}

impl<F> Div for SymbolicExt<F> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        SymbolicExt::Div(Rc::new(self), Rc::new(rhs))
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

impl<F> Neg for SymbolicExt<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        SymbolicExt::Neg(Rc::new(self))
    }
}

// Implement all operations between N, F, EF, and SymbolicVar<N>, SymbolicFelt<F>, SymbolicExt<F>

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

impl<F> Add<BinomialExtension<F>> for SymbolicExt<F> {
    type Output = Self;

    fn add(self, rhs: BinomialExtension<F>) -> Self::Output {
        SymbolicExt::Add(Rc::new(self), Rc::new(SymbolicExt::Const(rhs)))
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

impl<F> Mul<BinomialExtension<F>> for SymbolicExt<F> {
    type Output = Self;

    fn mul(self, rhs: BinomialExtension<F>) -> Self::Output {
        SymbolicExt::Mul(Rc::new(self), Rc::new(SymbolicExt::Const(rhs)))
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

impl<F> Sub<BinomialExtension<F>> for SymbolicExt<F> {
    type Output = Self;

    fn sub(self, rhs: BinomialExtension<F>) -> Self::Output {
        SymbolicExt::Sub(Rc::new(self), Rc::new(SymbolicExt::Const(rhs)))
    }
}

impl<F> Div<F> for SymbolicFelt<F> {
    type Output = Self;

    fn div(self, rhs: F) -> Self::Output {
        SymbolicFelt::Div(Rc::new(self), Rc::new(SymbolicFelt::Const(rhs)))
    }
}

impl<F> Div<BinomialExtension<F>> for SymbolicExt<F> {
    type Output = Self;

    fn div(self, rhs: BinomialExtension<F>) -> Self::Output {
        SymbolicExt::Div(Rc::new(self), Rc::new(SymbolicExt::Const(rhs)))
    }
}

// Implement all operations between SymbolicVar<N>, SymbolicFelt<F>, SymbolicExt<F>, and Var<N>,
//  Felt<F>, Ext<F>.

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

impl<F> Add<Ext<F>> for SymbolicExt<F> {
    type Output = SymbolicExt<F>;

    fn add(self, rhs: Ext<F>) -> Self::Output {
        self + SymbolicExt::from(rhs)
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

impl<F> Mul<Ext<F>> for SymbolicExt<F> {
    type Output = SymbolicExt<F>;

    fn mul(self, rhs: Ext<F>) -> Self::Output {
        self * SymbolicExt::from(rhs)
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

impl<F> Sub<Ext<F>> for SymbolicExt<F> {
    type Output = SymbolicExt<F>;

    fn sub(self, rhs: Ext<F>) -> Self::Output {
        self - SymbolicExt::from(rhs)
    }
}

impl<F> Div<SymbolicFelt<F>> for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn div(self, rhs: SymbolicFelt<F>) -> Self::Output {
        SymbolicFelt::<F>::from(self) / rhs
    }
}

impl<F> Div<SymbolicExt<F>> for Ext<F> {
    type Output = SymbolicExt<F>;

    fn div(self, rhs: SymbolicExt<F>) -> Self::Output {
        SymbolicExt::<F>::from(self) / rhs
    }
}

// Implement operations between constants N, F, EF, and Var<N>, Felt<F>, Ext<F>.

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

impl<F> Add for Ext<F> {
    type Output = SymbolicExt<F>;

    fn add(self, rhs: Self) -> Self::Output {
        SymbolicExt::<F>::from(self) + rhs
    }
}

impl<F> Add<BinomialExtension<F>> for Ext<F> {
    type Output = SymbolicExt<F>;

    fn add(self, rhs: BinomialExtension<F>) -> Self::Output {
        SymbolicExt::from(self) + rhs
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

impl<F> Mul for Ext<F> {
    type Output = SymbolicExt<F>;

    fn mul(self, rhs: Self) -> Self::Output {
        SymbolicExt::<F>::from(self) * rhs
    }
}

impl<F> Mul<BinomialExtension<F>> for Ext<F> {
    type Output = SymbolicExt<F>;

    fn mul(self, rhs: BinomialExtension<F>) -> Self::Output {
        SymbolicExt::from(self) * rhs
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

impl<F> Sub for Ext<F> {
    type Output = SymbolicExt<F>;

    fn sub(self, rhs: Self) -> Self::Output {
        SymbolicExt::<F>::from(self) - rhs
    }
}

impl<F> Sub<BinomialExtension<F>> for Ext<F> {
    type Output = SymbolicExt<F>;

    fn sub(self, rhs: BinomialExtension<F>) -> Self::Output {
        SymbolicExt::from(self) - rhs
    }
}

impl<F> Sub<SymbolicExt<F>> for Ext<F> {
    type Output = SymbolicExt<F>;

    fn sub(self, rhs: SymbolicExt<F>) -> Self::Output {
        SymbolicExt::<F>::from(self) - rhs
    }
}

impl<F> Add<SymbolicExt<F>> for Ext<F> {
    type Output = SymbolicExt<F>;

    fn add(self, rhs: SymbolicExt<F>) -> Self::Output {
        SymbolicExt::<F>::from(self) + rhs
    }
}

impl<F> Mul<SymbolicExt<F>> for Ext<F> {
    type Output = SymbolicExt<F>;

    fn mul(self, rhs: SymbolicExt<F>) -> Self::Output {
        SymbolicExt::<F>::from(self) * rhs
    }
}

impl<F> Add<SymbolicExt<F>> for Felt<F> {
    type Output = SymbolicExt<F>;

    fn add(self, rhs: SymbolicExt<F>) -> Self::Output {
        SymbolicExt::<F>::Base(Rc::new(SymbolicFelt::Val(self))) + rhs
    }
}

impl<F> Mul<SymbolicExt<F>> for Felt<F> {
    type Output = SymbolicExt<F>;

    fn mul(self, rhs: SymbolicExt<F>) -> Self::Output {
        SymbolicExt::<F>::Base(Rc::new(SymbolicFelt::Val(self))) * rhs
    }
}

impl<F> Sub<SymbolicExt<F>> for Felt<F> {
    type Output = SymbolicExt<F>;

    fn sub(self, rhs: SymbolicExt<F>) -> Self::Output {
        SymbolicExt::<F>::Base(Rc::new(SymbolicFelt::Val(self))) - rhs
    }
}

impl<F> Div<SymbolicExt<F>> for Felt<F> {
    type Output = SymbolicExt<F>;

    fn div(self, rhs: SymbolicExt<F>) -> Self::Output {
        SymbolicExt::<F>::Base(Rc::new(SymbolicFelt::Val(self))) / rhs
    }
}

impl<F> Div for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn div(self, rhs: Self) -> Self::Output {
        SymbolicFelt::<F>::from(self) / rhs
    }
}

impl<F> Div for Ext<F> {
    type Output = SymbolicExt<F>;

    fn div(self, rhs: Self) -> Self::Output {
        SymbolicExt::Div(
            Rc::new(SymbolicExt::from(self)),
            Rc::new(SymbolicExt::from(rhs)),
        )
    }
}

impl<F> Div<Felt<F>> for SymbolicFelt<F> {
    type Output = SymbolicFelt<F>;

    fn div(self, rhs: Felt<F>) -> Self::Output {
        SymbolicFelt::Div(Rc::new(self), Rc::new(SymbolicFelt::Val(rhs)))
    }
}

impl<F: Field + BinomiallyExtendable<D>> Product for SymbolicExt<F> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::one(), |acc, x| acc * x)
    }
}

impl<F: Field + BinomiallyExtendable<D>> Sum for SymbolicExt<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |acc, x| acc + x)
    }
}

impl<F: Field> MulAssign for SymbolicExt<F> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

impl<F: Field> SubAssign for SymbolicExt<F> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs;
    }
}

impl<F: Field> AddAssign for SymbolicExt<F> {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}

impl<F: Field + BinomiallyExtendable<D>> Default for SymbolicExt<F> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<F: Field + BinomiallyExtendable<D>> AbstractField for SymbolicExt<F> {
    type F = BinomialExtension<F>;

    fn zero() -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::zero())
    }

    fn one() -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::one())
    }

    fn two() -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::two())
    }

    fn neg_one() -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::neg_one())
    }

    fn from_f(f: Self::F) -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::from_f(f))
    }

    fn from_bool(b: bool) -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::from_bool(b))
    }

    fn from_canonical_u8(n: u8) -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::from_canonical_u8(n))
    }

    fn from_canonical_u16(n: u16) -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::from_canonical_u16(n))
    }

    fn from_canonical_u32(n: u32) -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::from_canonical_u32(n))
    }

    fn from_canonical_u64(n: u64) -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::from_canonical_u64(n))
    }

    fn from_canonical_usize(n: usize) -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::from_canonical_usize(n))
    }

    fn from_wrapped_u32(n: u32) -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::from_wrapped_u32(n))
    }

    fn from_wrapped_u64(n: u64) -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::from_wrapped_u64(n))
    }

    fn generator() -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::generator())
    }
}

impl<F: Field + BinomiallyExtendable<D>> AbstractExtensionField<F> for SymbolicExt<F> {
    const D: usize = F::D;

    fn from_base(b: F) -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::from_base(b))
    }

    fn from_base_slice(bs: &[F]) -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::from_base_slice(bs))
    }

    fn from_base_fn<T: FnMut(usize) -> F>(f: T) -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::from_base_fn(f))
    }

    fn as_base_slice(&self) -> &[F] {
        todo!()
    }
}

impl<F: Field + BinomiallyExtendable<D>> MulAssign<F> for SymbolicExt<F> {
    fn mul_assign(&mut self, rhs: F) {
        *self = self.clone() * SymbolicExt::Const(BinomialExtension::<F>::from_f(rhs.into()));
    }
}

impl<F: Field + BinomiallyExtendable<D>> Mul<F> for SymbolicExt<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        self * SymbolicExt::Const(BinomialExtension::<F>::from_f(rhs.into()))
    }
}

impl<F: Field + BinomiallyExtendable<D>> SubAssign<F> for SymbolicExt<F> {
    fn sub_assign(&mut self, rhs: F) {
        *self = self.clone() - SymbolicExt::Const(BinomialExtension::<F>::from_f(rhs.into()));
    }
}

impl<F: Field + BinomiallyExtendable<D>> Sub<F> for SymbolicExt<F> {
    type Output = Self;

    fn sub(self, rhs: F) -> Self::Output {
        self - SymbolicExt::Const(BinomialExtension::<F>::from_f(rhs.into()))
    }
}

impl<F: Field + BinomiallyExtendable<D>> AddAssign<F> for SymbolicExt<F> {
    fn add_assign(&mut self, rhs: F) {
        *self = self.clone() + SymbolicExt::Const(BinomialExtension::<F>::from_f(rhs.into()));
    }
}

impl<F: Field + BinomiallyExtendable<D>> Add<F> for SymbolicExt<F> {
    type Output = Self;

    fn add(self, rhs: F) -> Self::Output {
        self + SymbolicExt::Const(BinomialExtension::<F>::from_f(rhs.into()))
    }
}

impl<F: Field + BinomiallyExtendable<D>> From<F> for SymbolicExt<F> {
    fn from(f: F) -> Self {
        SymbolicExt::Const(BinomialExtension::<F>::from_f(f.into()))
    }
}

impl<F: Field + BinomiallyExtendable<D>> Add<F> for Ext<F> {
    type Output = SymbolicExt<F>;

    fn add(self, rhs: F) -> Self::Output {
        SymbolicExt::Val(self) + SymbolicExt::Const(BinomialExtension::<F>::from_f(rhs.into()))
    }
}

impl<F: Field + BinomiallyExtendable<D>> Sub<F> for Ext<F> {
    type Output = SymbolicExt<F>;

    fn sub(self, rhs: F) -> Self::Output {
        SymbolicExt::Val(self) - SymbolicExt::Const(BinomialExtension::<F>::from_f(rhs.into()))
    }
}

impl<F: Field + BinomiallyExtendable<D>> Mul<F> for Ext<F> {
    type Output = SymbolicExt<F>;

    fn mul(self, rhs: F) -> Self::Output {
        SymbolicExt::Val(self) * SymbolicExt::Const(BinomialExtension::<F>::from_f(rhs.into()))
    }
}

impl<F: Field + BinomiallyExtendable<D>> Mul<Ext<F>> for BinomialExtension<F> {
    type Output = SymbolicExt<F>;

    fn mul(self, rhs: Ext<F>) -> Self::Output {
        SymbolicExt::Val(rhs) * SymbolicExt::Const(self)
    }
}
