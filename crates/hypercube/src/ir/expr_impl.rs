use std::{
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use slop_algebra::{
    extension::BinomialExtensionField, AbstractExtensionField, AbstractField, Field, PrimeField32,
};
use sp1_primitives::SP1Field;

use crate::ir::{BinOp, ExprExtRef, ExprRef, GLOBAL_AST, IrVar};

pub(crate) type F = SP1Field;
pub(crate) type EF = BinomialExtensionField<SP1Field, 4>;
pub(crate) type Expr = ExprRef<F>;
pub(crate) type ExprExt = ExprExtRef<EF>;

impl AbstractField for Expr {
    type F = F;

    fn zero() -> Self {
        F::zero().into()
    }
    fn one() -> Self {
        F::one().into()
    }
    fn two() -> Self {
        F::two().into()
    }
    fn neg_one() -> Self {
        F::neg_one().into()
    }

    fn from_f(f: Self::F) -> Self {
        f.into()
    }
    fn from_bool(b: bool) -> Self {
        F::from_bool(b).into()
    }
    fn from_canonical_u8(n: u8) -> Self {
        F::from_canonical_u8(n).into()
    }
    fn from_canonical_u16(n: u16) -> Self {
        F::from_canonical_u16(n).into()
    }
    fn from_canonical_u32(n: u32) -> Self {
        F::from_canonical_u32(n).into()
    }
    fn from_canonical_u64(n: u64) -> Self {
        F::from_canonical_u64(n).into()
    }
    fn from_canonical_usize(n: usize) -> Self {
        F::from_canonical_usize(n).into()
    }
    fn from_wrapped_u32(n: u32) -> Self {
        F::from_wrapped_u32(n).into()
    }
    fn from_wrapped_u64(n: u64) -> Self {
        F::from_wrapped_u64(n).into()
    }

    fn generator() -> Self {
        F::generator().into()
    }
}

impl Add for Expr {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op(BinOp::Add, self, rhs)
    }
}

impl Sub for Expr {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op(BinOp::Sub, self, rhs)
    }
}

impl Mul for Expr {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op(BinOp::Mul, self, rhs)
    }
}

impl Neg for Expr {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.negate(self)
    }
}

impl Add<F> for Expr {
    type Output = Self;

    fn add(self, rhs: F) -> Self::Output {
        self + Expr::from(rhs)
    }
}

impl Sub<F> for Expr {
    type Output = Self;

    fn sub(self, rhs: F) -> Self::Output {
        self - Expr::from(rhs)
    }
}

impl Mul<F> for Expr {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        self * Expr::from(rhs)
    }
}

impl Sum for Expr {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(F::zero().into(), Add::add)
    }
}

impl Product for Expr {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(F::one().into(), Mul::mul)
    }
}

/// Recognize the precomputed inverse of a small canonical-u32 base. Used by
/// `From<F> for Expr` so the constraint compiler tags eagerly-computed
/// inverses symbolically when emitting Lean — the chip operation code (which
/// is shared with the prover) keeps its `from_canonical_u32(N).inverse()`
/// pattern, but the resulting Lean output is `((base : Fin KB)⁻¹)` instead
/// of the KoalaBear-specific literal.
fn recognize_inverse_base(value: F) -> Option<u32> {
    const KNOWN_BASES: &[u32] = &[4, 8, 64, 256, 65536];
    let v = value.as_canonical_u32();
    KNOWN_BASES.iter().copied().find(|&base| {
        let base_val = F::from_canonical_u32(base);
        base_val.as_canonical_u32() != v
            && base_val.inverse().as_canonical_u32() == v
    })
}

impl From<F> for Expr {
    fn from(f: F) -> Self {
        if let Some(base) = recognize_inverse_base(f) {
            Expr::IrVar(IrVar::InverseConstant { base, value: f })
        } else {
            Expr::IrVar(IrVar::Constant(f))
        }
    }
}

impl Default for Expr {
    fn default() -> Self {
        F::zero().into()
    }
}

impl AddAssign for Expr {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl SubAssign for Expr {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl MulAssign for Expr {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl AbstractField for ExprExt {
    type F = EF;

    fn zero() -> Self {
        EF::zero().into()
    }
    fn one() -> Self {
        EF::one().into()
    }
    fn two() -> Self {
        EF::two().into()
    }
    fn neg_one() -> Self {
        EF::neg_one().into()
    }

    fn from_f(f: Self::F) -> Self {
        f.into()
    }
    fn from_bool(b: bool) -> Self {
        EF::from_bool(b).into()
    }
    fn from_canonical_u8(n: u8) -> Self {
        EF::from_canonical_u8(n).into()
    }
    fn from_canonical_u16(n: u16) -> Self {
        EF::from_canonical_u16(n).into()
    }
    fn from_canonical_u32(n: u32) -> Self {
        EF::from_canonical_u32(n).into()
    }
    fn from_canonical_u64(n: u64) -> Self {
        EF::from_canonical_u64(n).into()
    }
    fn from_canonical_usize(n: usize) -> Self {
        EF::from_canonical_usize(n).into()
    }
    fn from_wrapped_u32(n: u32) -> Self {
        EF::from_wrapped_u32(n).into()
    }
    fn from_wrapped_u64(n: u64) -> Self {
        EF::from_wrapped_u64(n).into()
    }

    fn generator() -> Self {
        EF::generator().into()
    }
}

impl AbstractExtensionField<Expr> for ExprExt {
    const D: usize = <EF as AbstractExtensionField<F>>::D;

    fn from_base(b: Expr) -> Self {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.ext_from_base(b)
    }

    fn from_base_slice(_: &[Expr]) -> Self {
        todo!()
    }

    fn from_base_fn<F: FnMut(usize) -> Expr>(_: F) -> Self {
        todo!()
    }

    fn as_base_slice(&self) -> &[Expr] {
        todo!()
    }
}

impl From<Expr> for ExprExt {
    fn from(e: Expr) -> Self {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.ext_from_base(e)
    }
}

impl Add<Expr> for ExprExt {
    type Output = Self;

    fn add(self, rhs: Expr) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op_base_ext(BinOp::Add, self, rhs)
    }
}

impl Sub<Expr> for ExprExt {
    type Output = Self;

    fn sub(self, rhs: Expr) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op_base_ext(BinOp::Sub, self, rhs)
    }
}

impl Mul<Expr> for ExprExt {
    type Output = Self;

    fn mul(self, rhs: Expr) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op_base_ext(BinOp::Mul, self, rhs)
    }
}

impl MulAssign<Expr> for ExprExt {
    fn mul_assign(&mut self, rhs: Expr) {
        *self = *self * rhs;
    }
}

impl AddAssign<Expr> for ExprExt {
    fn add_assign(&mut self, rhs: Expr) {
        *self = *self + rhs;
    }
}

impl SubAssign<Expr> for ExprExt {
    fn sub_assign(&mut self, rhs: Expr) {
        *self = *self - rhs;
    }
}

impl Add for ExprExt {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op_ext(BinOp::Add, self, rhs)
    }
}

impl Sub for ExprExt {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op_ext(BinOp::Sub, self, rhs)
    }
}

impl Mul for ExprExt {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.bin_op_ext(BinOp::Mul, self, rhs)
    }
}

impl Neg for ExprExt {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut ast = GLOBAL_AST.lock().unwrap();
        ast.neg_ext(self)
    }
}

impl From<EF> for ExprExt {
    fn from(f: EF) -> Self {
        ExprExtRef::ExtConstant(f)
    }
}

impl Default for ExprExt {
    fn default() -> Self {
        EF::zero().into()
    }
}

impl AddAssign for ExprExt {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl SubAssign for ExprExt {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl MulAssign for ExprExt {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Sum for ExprExt {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(EF::zero().into(), Add::add)
    }
}

impl Product for ExprExt {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(EF::one().into(), Mul::mul)
    }
}
