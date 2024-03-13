use super::{Ext, Felt, Var};
use alloc::rc::Rc;
use core::ops::{Add, Div, Mul, Neg, Sub};
use p3_field::ExtensionField;
use p3_field::Field;

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

impl<F, EF> From<EF> for SymbolicExt<F, EF> {
    fn from(ef: EF) -> Self {
        SymbolicExt::Const(ef)
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

impl<F, EF> From<Ext<F, EF>> for SymbolicExt<F, EF> {
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

impl<F, EF> Add for SymbolicExt<F, EF> {
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

impl<F, EF> Mul for SymbolicExt<F, EF> {
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

impl<F, EF> Sub for SymbolicExt<F, EF> {
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

impl<F, EF> Div for SymbolicExt<F, EF> {
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

impl<F, EF> Neg for SymbolicExt<F, EF> {
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

impl<F, EF> Add<EF> for SymbolicExt<F, EF> {
    type Output = Self;

    fn add(self, rhs: EF) -> Self::Output {
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

impl<F, EF> Mul<EF> for SymbolicExt<F, EF> {
    type Output = Self;

    fn mul(self, rhs: EF) -> Self::Output {
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

impl<F, EF> Sub<EF> for SymbolicExt<F, EF> {
    type Output = Self;

    fn sub(self, rhs: EF) -> Self::Output {
        SymbolicExt::Sub(Rc::new(self), Rc::new(SymbolicExt::Const(rhs)))
    }
}

impl<F> Div<F> for SymbolicFelt<F> {
    type Output = Self;

    fn div(self, rhs: F) -> Self::Output {
        SymbolicFelt::Div(Rc::new(self), Rc::new(SymbolicFelt::Const(rhs)))
    }
}

impl<F, EF> Div<EF> for SymbolicExt<F, EF> {
    type Output = Self;

    fn div(self, rhs: EF) -> Self::Output {
        SymbolicExt::Div(Rc::new(self), Rc::new(SymbolicExt::Const(rhs)))
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

impl<F, EF> Add<Ext<F, EF>> for SymbolicExt<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn add(self, rhs: Ext<F, EF>) -> Self::Output {
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

impl<F, EF> Mul<Ext<F, EF>> for SymbolicExt<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn mul(self, rhs: Ext<F, EF>) -> Self::Output {
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

impl<F, EF> Sub<Ext<F, EF>> for SymbolicExt<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn sub(self, rhs: Ext<F, EF>) -> Self::Output {
        self - SymbolicExt::from(rhs)
    }
}

impl<F> Div<SymbolicFelt<F>> for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn div(self, rhs: SymbolicFelt<F>) -> Self::Output {
        SymbolicFelt::<F>::from(self) / rhs
    }
}

impl<F, EF> Div<SymbolicExt<F, EF>> for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn div(self, rhs: SymbolicExt<F, EF>) -> Self::Output {
        SymbolicExt::<F, EF>::from(self) / rhs
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

impl<F: Field, EF: ExtensionField<F>> Add for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn add(self, rhs: Self) -> Self::Output {
        SymbolicExt::<F, EF>::from(self) + rhs
    }
}

impl<F: Field, EF: ExtensionField<F>> Add<EF> for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn add(self, rhs: EF) -> Self::Output {
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

impl<F: Field, EF: ExtensionField<F>> Mul for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn mul(self, rhs: Self) -> Self::Output {
        SymbolicExt::<F, EF>::from(self) * rhs
    }
}

impl<F, EF> Mul<EF> for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn mul(self, rhs: EF) -> Self::Output {
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

impl<F: Field, EF: ExtensionField<F>> Sub for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn sub(self, rhs: Self) -> Self::Output {
        SymbolicExt::<F, EF>::from(self) - rhs
    }
}

impl<F, EF> Sub<EF> for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;

    fn sub(self, rhs: EF) -> Self::Output {
        SymbolicExt::from(self) - rhs
    }
}

impl<F> Div for Felt<F> {
    type Output = SymbolicFelt<F>;

    fn div(self, rhs: Self) -> Self::Output {
        SymbolicFelt::<F>::from(self) / rhs
    }
}

impl<F, EF> Div for Ext<F, EF> {
    type Output = SymbolicExt<F, EF>;

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
