//! Expr types — `NodeId` wrappers for arbitrary DAG computations.
//!
//! `DagExprF` represents a base-field expression; `DagExprEF` represents an
//! extension-field expression. Both are thin newtypes around `NodeId`. All
//! operator overloads allocate new DAG nodes via the global state.

use std::iter::{Product, Sum};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use slop_algebra::{AbstractExtensionField, AbstractField};

use crate::ir::dag::{DagNode, NodeId};
use crate::ir::state::with_state;
use crate::ir::var::{DagVarEF, DagVarF};
use crate::{EF, F};

// ============================================================================
// DagExprF
// ============================================================================

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct DagExprF(pub NodeId);

impl DagExprF {
    pub fn node_id(self) -> NodeId {
        self.0
    }
}

impl Default for DagExprF {
    fn default() -> Self {
        Self::zero()
    }
}

impl From<F> for DagExprF {
    fn from(f: F) -> Self {
        let id = with_state(|s| s.intern_const_f(f));
        DagExprF(id)
    }
}

// ----- Add -----
impl Add<F> for DagExprF {
    type Output = Self;
    fn add(self, rhs: F) -> Self::Output {
        let a = self.0;
        let id = with_state(|s| {
            let b = s.intern_const_f(rhs);
            s.alloc(DagNode::AddF { a, b })
        });
        DagExprF(id)
    }
}

impl Add<DagVarF> for DagExprF {
    type Output = Self;
    fn add(self, rhs: DagVarF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::AddF { a, b }));
        DagExprF(id)
    }
}

impl Add<DagExprF> for DagExprF {
    type Output = Self;
    fn add(self, rhs: DagExprF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::AddF { a, b }));
        DagExprF(id)
    }
}

impl AddAssign for DagExprF {
    fn add_assign(&mut self, rhs: Self) {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::AddF { a, b }));
        self.0 = id;
    }
}

// ----- Sub -----
impl Sub<F> for DagExprF {
    type Output = Self;
    fn sub(self, rhs: F) -> Self::Output {
        let a = self.0;
        let id = with_state(|s| {
            let b = s.intern_const_f(rhs);
            s.alloc(DagNode::SubF { a, b })
        });
        DagExprF(id)
    }
}

impl Sub<DagVarF> for DagExprF {
    type Output = Self;
    fn sub(self, rhs: DagVarF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::SubF { a, b }));
        DagExprF(id)
    }
}

impl Sub<DagExprF> for DagExprF {
    type Output = Self;
    fn sub(self, rhs: DagExprF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::SubF { a, b }));
        DagExprF(id)
    }
}

impl SubAssign for DagExprF {
    fn sub_assign(&mut self, rhs: Self) {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::SubF { a, b }));
        self.0 = id;
    }
}

// ----- Mul -----
impl Mul<F> for DagExprF {
    type Output = Self;
    fn mul(self, rhs: F) -> Self::Output {
        let a = self.0;
        let id = with_state(|s| {
            let b = s.intern_const_f(rhs);
            s.alloc(DagNode::MulF { a, b })
        });
        DagExprF(id)
    }
}

impl Mul<DagVarF> for DagExprF {
    type Output = Self;
    fn mul(self, rhs: DagVarF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::MulF { a, b }));
        DagExprF(id)
    }
}

impl Mul<DagExprF> for DagExprF {
    type Output = Self;
    fn mul(self, rhs: DagExprF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::MulF { a, b }));
        DagExprF(id)
    }
}

impl MulAssign for DagExprF {
    fn mul_assign(&mut self, rhs: Self) {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::MulF { a, b }));
        self.0 = id;
    }
}

// ----- Neg -----
impl Neg for DagExprF {
    type Output = Self;
    fn neg(self) -> Self::Output {
        let a = self.0;
        let id = with_state(|s| s.alloc(DagNode::NegF { a }));
        DagExprF(id)
    }
}

impl Sum for DagExprF {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |acc, x| acc + x)
    }
}

impl Product for DagExprF {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::one(), |acc, x| acc * x)
    }
}

impl AbstractField for DagExprF {
    type F = F;

    fn zero() -> Self {
        let id = with_state(|s| s.intern_const_f(F::zero()));
        DagExprF(id)
    }
    fn one() -> Self {
        let id = with_state(|s| s.intern_const_f(F::one()));
        DagExprF(id)
    }
    fn two() -> Self {
        let id = with_state(|s| s.intern_const_f(F::two()));
        DagExprF(id)
    }
    fn neg_one() -> Self {
        let id = with_state(|s| s.intern_const_f(F::neg_one()));
        DagExprF(id)
    }
    fn from_f(f: Self::F) -> Self {
        let id = with_state(|s| s.intern_const_f(f));
        DagExprF(id)
    }
    fn from_bool(b: bool) -> Self {
        let id = with_state(|s| s.intern_const_f(F::from_bool(b)));
        DagExprF(id)
    }
    fn from_canonical_u8(n: u8) -> Self {
        let id = with_state(|s| s.intern_const_f(F::from_canonical_u8(n)));
        DagExprF(id)
    }
    fn from_canonical_u16(n: u16) -> Self {
        let id = with_state(|s| s.intern_const_f(F::from_canonical_u16(n)));
        DagExprF(id)
    }
    fn from_canonical_u32(n: u32) -> Self {
        let id = with_state(|s| s.intern_const_f(F::from_canonical_u32(n)));
        DagExprF(id)
    }
    fn from_canonical_u64(n: u64) -> Self {
        let id = with_state(|s| s.intern_const_f(F::from_canonical_u64(n)));
        DagExprF(id)
    }
    fn from_canonical_usize(n: usize) -> Self {
        let id = with_state(|s| s.intern_const_f(F::from_canonical_usize(n)));
        DagExprF(id)
    }
    fn from_wrapped_u32(n: u32) -> Self {
        let id = with_state(|s| s.intern_const_f(F::from_wrapped_u32(n)));
        DagExprF(id)
    }
    fn from_wrapped_u64(n: u64) -> Self {
        let id = with_state(|s| s.intern_const_f(F::from_wrapped_u64(n)));
        DagExprF(id)
    }
    fn generator() -> Self {
        let id = with_state(|s| s.intern_const_f(F::generator()));
        DagExprF(id)
    }
}

// ============================================================================
// DagExprEF
// ============================================================================

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct DagExprEF(pub NodeId);

impl DagExprEF {
    pub fn node_id(self) -> NodeId {
        self.0
    }
}

impl Default for DagExprEF {
    fn default() -> Self {
        Self::zero()
    }
}

impl From<EF> for DagExprEF {
    fn from(f: EF) -> Self {
        let id = with_state(|s| s.intern_const_ef(f));
        DagExprEF(id)
    }
}

// ----- Add -----
impl Add<EF> for DagExprEF {
    type Output = Self;
    fn add(self, rhs: EF) -> Self::Output {
        let a = self.0;
        let id = with_state(|s| {
            let b = s.intern_const_ef(rhs);
            s.alloc(DagNode::AddEF { a, b })
        });
        DagExprEF(id)
    }
}

impl Add<DagVarEF> for DagExprEF {
    type Output = Self;
    fn add(self, rhs: DagVarEF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::AddEF { a, b }));
        DagExprEF(id)
    }
}

impl Add<DagExprEF> for DagExprEF {
    type Output = Self;
    fn add(self, rhs: DagExprEF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::AddEF { a, b }));
        DagExprEF(id)
    }
}

impl AddAssign for DagExprEF {
    fn add_assign(&mut self, rhs: Self) {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::AddEF { a, b }));
        self.0 = id;
    }
}

// ----- Sub -----
impl Sub<EF> for DagExprEF {
    type Output = Self;
    fn sub(self, rhs: EF) -> Self::Output {
        let a = self.0;
        let id = with_state(|s| {
            let b = s.intern_const_ef(rhs);
            s.alloc(DagNode::SubEF { a, b })
        });
        DagExprEF(id)
    }
}

impl Sub<DagVarEF> for DagExprEF {
    type Output = Self;
    fn sub(self, rhs: DagVarEF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::SubEF { a, b }));
        DagExprEF(id)
    }
}

impl Sub<DagExprEF> for DagExprEF {
    type Output = Self;
    fn sub(self, rhs: DagExprEF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::SubEF { a, b }));
        DagExprEF(id)
    }
}

impl SubAssign for DagExprEF {
    fn sub_assign(&mut self, rhs: Self) {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::SubEF { a, b }));
        self.0 = id;
    }
}

// ----- Mul -----
impl Mul<EF> for DagExprEF {
    type Output = Self;
    fn mul(self, rhs: EF) -> Self::Output {
        let a = self.0;
        let id = with_state(|s| {
            let b = s.intern_const_ef(rhs);
            s.alloc(DagNode::MulEF { a, b })
        });
        DagExprEF(id)
    }
}

impl Mul<DagExprEF> for DagExprEF {
    type Output = Self;
    fn mul(self, rhs: DagExprEF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::MulEF { a, b }));
        DagExprEF(id)
    }
}

impl MulAssign for DagExprEF {
    fn mul_assign(&mut self, rhs: Self) {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::MulEF { a, b }));
        self.0 = id;
    }
}

// ----- Neg -----
impl Neg for DagExprEF {
    type Output = Self;
    fn neg(self) -> Self::Output {
        let a = self.0;
        let id = with_state(|s| s.alloc(DagNode::NegEF { a }));
        DagExprEF(id)
    }
}

impl Sum for DagExprEF {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |acc, x| acc + x)
    }
}

impl Product for DagExprEF {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::one(), |acc, x| acc * x)
    }
}

impl AbstractField for DagExprEF {
    type F = EF;

    fn zero() -> Self {
        let id = with_state(|s| s.intern_const_ef(EF::zero()));
        DagExprEF(id)
    }
    fn one() -> Self {
        let id = with_state(|s| s.intern_const_ef(EF::one()));
        DagExprEF(id)
    }
    fn two() -> Self {
        let id = with_state(|s| s.intern_const_ef(EF::two()));
        DagExprEF(id)
    }
    fn neg_one() -> Self {
        let id = with_state(|s| s.intern_const_ef(EF::neg_one()));
        DagExprEF(id)
    }
    fn from_f(f: Self::F) -> Self {
        let id = with_state(|s| s.intern_const_ef(f));
        DagExprEF(id)
    }
    fn from_bool(b: bool) -> Self {
        let id = with_state(|s| s.intern_const_ef(EF::from_bool(b)));
        DagExprEF(id)
    }
    fn from_canonical_u8(n: u8) -> Self {
        let id = with_state(|s| s.intern_const_ef(EF::from_canonical_u8(n)));
        DagExprEF(id)
    }
    fn from_canonical_u16(n: u16) -> Self {
        let id = with_state(|s| s.intern_const_ef(EF::from_canonical_u16(n)));
        DagExprEF(id)
    }
    fn from_canonical_u32(n: u32) -> Self {
        let id = with_state(|s| s.intern_const_ef(EF::from_canonical_u32(n)));
        DagExprEF(id)
    }
    fn from_canonical_u64(n: u64) -> Self {
        let id = with_state(|s| s.intern_const_ef(EF::from_canonical_u64(n)));
        DagExprEF(id)
    }
    fn from_canonical_usize(n: usize) -> Self {
        let id = with_state(|s| s.intern_const_ef(EF::from_canonical_usize(n)));
        DagExprEF(id)
    }
    fn from_wrapped_u32(n: u32) -> Self {
        let id = with_state(|s| s.intern_const_ef(EF::from_wrapped_u32(n)));
        DagExprEF(id)
    }
    fn from_wrapped_u64(n: u64) -> Self {
        let id = with_state(|s| s.intern_const_ef(EF::from_wrapped_u64(n)));
        DagExprEF(id)
    }
    fn generator() -> Self {
        let id = with_state(|s| s.intern_const_ef(EF::generator()));
        DagExprEF(id)
    }
}

// ----- Mixed (DagExprEF, DagExprF) -----

impl From<DagExprF> for DagExprEF {
    fn from(v: DagExprF) -> Self {
        let a = v.0;
        let id = with_state(|s| s.alloc(DagNode::EFFromF { a }));
        DagExprEF(id)
    }
}

impl Add<DagExprF> for DagExprEF {
    type Output = Self;
    fn add(self, rhs: DagExprF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::EFAddF { a, b }));
        DagExprEF(id)
    }
}

impl AddAssign<DagExprF> for DagExprEF {
    fn add_assign(&mut self, rhs: DagExprF) {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::EFAddF { a, b }));
        self.0 = id;
    }
}

impl Sub<DagExprF> for DagExprEF {
    type Output = Self;
    fn sub(self, rhs: DagExprF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::EFSubF { a, b }));
        DagExprEF(id)
    }
}

impl SubAssign<DagExprF> for DagExprEF {
    fn sub_assign(&mut self, rhs: DagExprF) {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::EFSubF { a, b }));
        self.0 = id;
    }
}

impl Mul<DagExprF> for DagExprEF {
    type Output = DagExprEF;
    fn mul(self, rhs: DagExprF) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::EFMulF { a, b }));
        DagExprEF(id)
    }
}

impl MulAssign<DagExprF> for DagExprEF {
    fn mul_assign(&mut self, rhs: DagExprF) {
        let a = self.0;
        let b = rhs.0;
        let id = with_state(|s| s.alloc(DagNode::EFMulF { a, b }));
        self.0 = id;
    }
}

impl AbstractExtensionField<DagExprF> for DagExprEF {
    const D: usize = 4;

    fn from_base(value: DagExprF) -> Self {
        let a = value.0;
        let id = with_state(|s| s.alloc(DagNode::EFFromF { a }));
        DagExprEF(id)
    }

    fn from_base_slice(_: &[DagExprF]) -> Self {
        todo!()
    }

    fn from_base_fn<Func: FnMut(usize) -> DagExprF>(_: Func) -> Self {
        todo!()
    }

    fn as_base_slice(&self) -> &[DagExprF] {
        todo!()
    }
}
