use alloc::rc::Rc;
use core::{
    any::Any,
    ops::{Add, Div, Mul, Neg, Sub},
};
use std::{
    any::TypeId,
    hash::Hash,
    iter::{Product, Sum},
    mem,
    ops::{AddAssign, DivAssign, MulAssign, SubAssign},
};

use p3_field::{AbstractField, ExtensionField, Field, FieldArray};

use super::{Ext, Felt, Usize, Var};

const NUM_RANDOM_ELEMENTS: usize = 4;

pub type Digest<T> = FieldArray<T, NUM_RANDOM_ELEMENTS>;

pub fn elements<F: Field>() -> Digest<F> {
    let powers = [1671541671, 1254988180, 442438744, 1716490559];
    let generator = F::generator();

    Digest::from(powers.map(|p| generator.exp_u64(p)))
}

pub fn ext_elements<F: Field, EF: ExtensionField<F>>() -> Digest<EF> {
    let powers = [1021539871, 1430550064, 447478069, 1248903325];
    let generator = EF::generator();

    Digest::from(powers.map(|p| generator.exp_u64(p)))
}

fn digest_id<F: Field>(id: u32) -> Digest<F> {
    let elements = elements();
    Digest::from(
        elements.0.map(|e: F| (e + F::from_canonical_u32(id)).try_inverse().unwrap_or(F::one())),
    )
}

fn digest_id_ext<F: Field, EF: ExtensionField<F>>(id: u32) -> Digest<EF> {
    let elements = ext_elements();
    Digest::from(
        elements.0.map(|e: EF| (e + EF::from_canonical_u32(id)).try_inverse().unwrap_or(EF::one())),
    )
}

fn div_digests<F: Field>(a: Digest<F>, b: Digest<F>) -> Digest<F> {
    Digest::from(core::array::from_fn(|i| a.0[i] / b.0[i]))
}

#[derive(Debug, Clone)]
pub enum SymbolicVar<N: Field> {
    Const(N, Digest<N>),
    Val(Var<N>, Digest<N>),
    Add(Rc<SymbolicVar<N>>, Rc<SymbolicVar<N>>, Digest<N>),
    Mul(Rc<SymbolicVar<N>>, Rc<SymbolicVar<N>>, Digest<N>),
    Sub(Rc<SymbolicVar<N>>, Rc<SymbolicVar<N>>, Digest<N>),
    Neg(Rc<SymbolicVar<N>>, Digest<N>),
}

#[derive(Debug, Clone)]
pub enum SymbolicFelt<F: Field> {
    Const(F, Digest<F>),
    Val(Felt<F>, Digest<F>),
    Add(Rc<SymbolicFelt<F>>, Rc<SymbolicFelt<F>>, Digest<F>),
    Mul(Rc<SymbolicFelt<F>>, Rc<SymbolicFelt<F>>, Digest<F>),
    Sub(Rc<SymbolicFelt<F>>, Rc<SymbolicFelt<F>>, Digest<F>),
    Div(Rc<SymbolicFelt<F>>, Rc<SymbolicFelt<F>>, Digest<F>),
    Neg(Rc<SymbolicFelt<F>>, Digest<F>),
}

#[derive(Debug, Clone)]
pub enum SymbolicExt<F: Field, EF: Field> {
    Const(EF, Digest<EF>),
    Base(Rc<SymbolicFelt<F>>, Digest<EF>),
    Val(Ext<F, EF>, Digest<EF>),
    Add(Rc<SymbolicExt<F, EF>>, Rc<SymbolicExt<F, EF>>, Digest<EF>),
    Mul(Rc<SymbolicExt<F, EF>>, Rc<SymbolicExt<F, EF>>, Digest<EF>),
    Sub(Rc<SymbolicExt<F, EF>>, Rc<SymbolicExt<F, EF>>, Digest<EF>),
    Div(Rc<SymbolicExt<F, EF>>, Rc<SymbolicExt<F, EF>>, Digest<EF>),
    Neg(Rc<SymbolicExt<F, EF>>, Digest<EF>),
}

impl<N: Field> Hash for SymbolicVar<N> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for elem in self.digest().0.iter() {
            elem.hash(state);
        }
    }
}

impl<N: Field> PartialEq for SymbolicVar<N> {
    fn eq(&self, other: &Self) -> bool {
        self.digest() == other.digest()
    }
}

impl<N: Field> Eq for SymbolicVar<N> {}

impl<F: Field> Hash for SymbolicFelt<F> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for elem in self.digest().0.iter() {
            elem.hash(state);
        }
    }
}

impl<F: Field> PartialEq for SymbolicFelt<F> {
    fn eq(&self, other: &Self) -> bool {
        self.digest() == other.digest()
    }
}

impl<F: Field> Eq for SymbolicFelt<F> {}

impl<F: Field, EF: Field> Hash for SymbolicExt<F, EF> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for elem in self.digest().0.iter() {
            elem.hash(state);
        }
    }
}

impl<F: Field, EF: Field> PartialEq for SymbolicExt<F, EF> {
    fn eq(&self, other: &Self) -> bool {
        self.digest() == other.digest()
    }
}

impl<F: Field, EF: Field> Eq for SymbolicExt<F, EF> {}

impl<N: Field> SymbolicVar<N> {
    pub(crate) const fn digest(&self) -> Digest<N> {
        match self {
            SymbolicVar::Const(_, d) => *d,
            SymbolicVar::Val(_, d) => *d,
            SymbolicVar::Add(_, _, d) => *d,
            SymbolicVar::Mul(_, _, d) => *d,
            SymbolicVar::Sub(_, _, d) => *d,
            SymbolicVar::Neg(_, d) => *d,
        }
    }
}

impl<F: Field> SymbolicFelt<F> {
    pub(crate) const fn digest(&self) -> Digest<F> {
        match self {
            SymbolicFelt::Const(_, d) => *d,
            SymbolicFelt::Val(_, d) => *d,
            SymbolicFelt::Add(_, _, d) => *d,
            SymbolicFelt::Mul(_, _, d) => *d,
            SymbolicFelt::Sub(_, _, d) => *d,
            SymbolicFelt::Div(_, _, d) => *d,
            SymbolicFelt::Neg(_, d) => *d,
        }
    }
}

impl<F: Field, EF: Field> SymbolicExt<F, EF> {
    pub(crate) const fn digest(&self) -> Digest<EF> {
        match self {
            SymbolicExt::Const(_, d) => *d,
            SymbolicExt::Base(_, d) => *d,
            SymbolicExt::Val(_, d) => *d,
            SymbolicExt::Add(_, _, d) => *d,
            SymbolicExt::Mul(_, _, d) => *d,
            SymbolicExt::Sub(_, _, d) => *d,
            SymbolicExt::Div(_, _, d) => *d,
            SymbolicExt::Neg(_, d) => *d,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub fn digest(&self) -> Digest<EF> {
        match self {
            ExtOperand::Base(f) => SymbolicFelt::from(*f).digest().0.map(EF::from_base).into(),
            ExtOperand::Const(ef) => (*ef).into(),
            ExtOperand::Felt(f) => SymbolicFelt::from(*f).digest().0.map(EF::from_base).into(),
            ExtOperand::Ext(e) => digest_id_ext::<F, EF>(e.0),
            ExtOperand::SymFelt(f) => f.digest().0.map(EF::from_base).into(),
            ExtOperand::Sym(e) => e.digest(),
        }
    }

    pub fn symbolic(self) -> SymbolicExt<F, EF> {
        let digest = self.digest();
        match self {
            ExtOperand::Base(f) => SymbolicExt::Base(Rc::new(SymbolicFelt::from(f)), digest),
            ExtOperand::Const(ef) => SymbolicExt::Const(ef, digest),
            ExtOperand::Felt(f) => SymbolicExt::Base(Rc::new(SymbolicFelt::from(f)), digest),
            ExtOperand::Ext(e) => SymbolicExt::Val(e, digest),
            ExtOperand::SymFelt(f) => SymbolicExt::Base(Rc::new(f), digest),
            ExtOperand::Sym(e) => e,
        }
    }
}

pub trait ExtConst<F: Field, EF: ExtensionField<F>> {
    fn cons(self) -> SymbolicExt<F, EF>;
}

impl<F: Field, EF: ExtensionField<F>> ExtConst<F, EF> for EF {
    fn cons(self) -> SymbolicExt<F, EF> {
        SymbolicExt::Const(self, self.into())
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
        SymbolicExt::Const(f, f.into())
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
        SymbolicVar::Const(n, n.into())
    }
}

impl<F: Field> From<F> for SymbolicFelt<F> {
    fn from(f: F) -> Self {
        SymbolicFelt::Const(f, f.into())
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
        SymbolicVar::Val(v, digest_id(v.0))
    }
}

impl<F: Field> From<Felt<F>> for SymbolicFelt<F> {
    fn from(f: Felt<F>) -> Self {
        SymbolicFelt::Val(f, digest_id(f.0))
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
        let digest = self.digest() + rhs.digest();
        SymbolicVar::Add(Rc::new(self), Rc::new(rhs), digest)
    }
}

impl<F: Field> Add for SymbolicFelt<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let digest = self.digest() + rhs.digest();
        SymbolicFelt::Add(Rc::new(self), Rc::new(rhs), digest)
    }
}

impl<F: Field, EF: ExtensionField<F>, E: ExtensionOperand<F, EF>> Add<E> for SymbolicExt<F, EF> {
    type Output = Self;

    fn add(self, rhs: E) -> Self::Output {
        let rhs = rhs.to_operand().symbolic();
        let digest = self.digest() + rhs.digest();
        SymbolicExt::Add(Rc::new(self), Rc::new(rhs), digest)
    }
}

impl<N: Field> Mul for SymbolicVar<N> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let digest = self.digest() * rhs.digest();
        SymbolicVar::Mul(Rc::new(self), Rc::new(rhs), digest)
    }
}

impl<F: Field> Mul for SymbolicFelt<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let digest = self.digest() * rhs.digest();
        SymbolicFelt::Mul(Rc::new(self), Rc::new(rhs), digest)
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Mul<E> for SymbolicExt<F, EF> {
    type Output = Self;

    fn mul(self, rhs: E) -> Self::Output {
        let rhs = rhs.to_operand();
        let rhs_digest = rhs.digest();
        let prod_digest = self.digest() * rhs_digest;
        match rhs {
            ExtOperand::Base(f) => SymbolicExt::Mul(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::from(f)), rhs_digest)),
                prod_digest,
            ),
            ExtOperand::Const(ef) => SymbolicExt::Mul(
                Rc::new(self),
                Rc::new(SymbolicExt::Const(ef, rhs_digest)),
                prod_digest,
            ),
            ExtOperand::Felt(f) => SymbolicExt::Mul(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::from(f)), rhs_digest)),
                prod_digest,
            ),
            ExtOperand::Ext(e) => SymbolicExt::Mul(
                Rc::new(self),
                Rc::new(SymbolicExt::Val(e, rhs_digest)),
                prod_digest,
            ),
            ExtOperand::SymFelt(f) => SymbolicExt::Mul(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(f), rhs_digest)),
                prod_digest,
            ),
            ExtOperand::Sym(e) => SymbolicExt::Mul(Rc::new(self), Rc::new(e), prod_digest),
        }
    }
}

impl<N: Field> Sub for SymbolicVar<N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let digest = self.digest() - rhs.digest();
        SymbolicVar::Sub(Rc::new(self), Rc::new(rhs), digest)
    }
}

impl<F: Field> Sub for SymbolicFelt<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let digest = self.digest() - rhs.digest();
        SymbolicFelt::Sub(Rc::new(self), Rc::new(rhs), digest)
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Sub<E> for SymbolicExt<F, EF> {
    type Output = Self;

    fn sub(self, rhs: E) -> Self::Output {
        let rhs = rhs.to_operand();
        let rhs_digest = rhs.digest();
        let digest = self.digest() - rhs_digest;
        match rhs {
            ExtOperand::Base(f) => SymbolicExt::Sub(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::from(f)), rhs_digest)),
                digest,
            ),
            ExtOperand::Const(ef) => {
                SymbolicExt::Sub(Rc::new(self), Rc::new(SymbolicExt::Const(ef, rhs_digest)), digest)
            }
            ExtOperand::Felt(f) => SymbolicExt::Sub(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::from(f)), rhs_digest)),
                digest,
            ),
            ExtOperand::Ext(e) => {
                SymbolicExt::Sub(Rc::new(self), Rc::new(SymbolicExt::Val(e, rhs_digest)), digest)
            }
            ExtOperand::SymFelt(f) => SymbolicExt::Sub(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(f), rhs_digest)),
                digest,
            ),
            ExtOperand::Sym(e) => SymbolicExt::Sub(Rc::new(self), Rc::new(e), digest),
        }
    }
}

impl<F: Field> Div for SymbolicFelt<F> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let self_digest = self.digest();
        let rhs_digest = rhs.digest();
        let digest = div_digests(self_digest, rhs_digest);
        SymbolicFelt::Div(Rc::new(self), Rc::new(rhs), digest)
    }
}

impl<F: Field, EF: ExtensionField<F>, E: Any> Div<E> for SymbolicExt<F, EF> {
    type Output = Self;

    fn div(self, rhs: E) -> Self::Output {
        let rhs = rhs.to_operand();
        let rhs_digest = rhs.digest();
        let digest = div_digests(self.digest(), rhs_digest);
        match rhs {
            ExtOperand::Base(f) => SymbolicExt::Div(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::from(f)), rhs_digest)),
                digest,
            ),
            ExtOperand::Const(ef) => {
                SymbolicExt::Div(Rc::new(self), Rc::new(SymbolicExt::Const(ef, rhs_digest)), digest)
            }
            ExtOperand::Felt(f) => SymbolicExt::Div(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(SymbolicFelt::from(f)), rhs_digest)),
                digest,
            ),
            ExtOperand::Ext(e) => {
                SymbolicExt::Div(Rc::new(self), Rc::new(SymbolicExt::Val(e, rhs_digest)), digest)
            }
            ExtOperand::SymFelt(f) => SymbolicExt::Div(
                Rc::new(self),
                Rc::new(SymbolicExt::Base(Rc::new(f), rhs_digest)),
                digest,
            ),
            ExtOperand::Sym(e) => SymbolicExt::Div(Rc::new(self), Rc::new(e), digest),
        }
    }
}

impl<N: Field> Neg for SymbolicVar<N> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let digest = -self.digest();
        SymbolicVar::Neg(Rc::new(self), digest)
    }
}

impl<F: Field> Neg for SymbolicFelt<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let digest = -self.digest();
        SymbolicFelt::Neg(Rc::new(self), digest)
    }
}

impl<F: Field, EF: ExtensionField<F>> Neg for SymbolicExt<F, EF> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let digest = -self.digest();
        SymbolicExt::Neg(Rc::new(self), digest)
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
        let digest = self.digest() - rhs;
        SymbolicVar::Sub(Rc::new(self), Rc::new(SymbolicVar::from_f(rhs)), digest)
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
        *self = self.clone() * Self::from(rhs);
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
