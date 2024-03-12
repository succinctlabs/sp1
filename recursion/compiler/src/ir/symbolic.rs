use super::{Config, Ext, Felt, Var};
use alloc::rc::Rc;
use core::ops::{Add, Div, Mul, Neg, Sub};

pub enum SymbolicVar<C: Config> {
    Const(C::N),
    Val(Var<C>),
    Add(Rc<SymbolicVar<C>>, Rc<SymbolicVar<C>>),
    Mul(Rc<SymbolicVar<C>>, Rc<SymbolicVar<C>>),
    Sub(Rc<SymbolicVar<C>>, Rc<SymbolicVar<C>>),
    Neg(Rc<SymbolicVar<C>>),
}

pub enum SymbolicFelt<C: Config> {
    Const(C::F),
    Val(Felt<C>),
    Add(Rc<SymbolicFelt<C>>, Rc<SymbolicFelt<C>>),
    Mul(Rc<SymbolicFelt<C>>, Rc<SymbolicFelt<C>>),
    Sub(Rc<SymbolicFelt<C>>, Rc<SymbolicFelt<C>>),
    Div(Rc<SymbolicFelt<C>>, Rc<SymbolicFelt<C>>),
    Neg(Rc<SymbolicFelt<C>>),
}

pub enum SymbolicExt<C: Config> {
    Const(C::EF),
    Base(Rc<SymbolicFelt<C>>),
    Val(Ext<C>),
    Add(Rc<SymbolicExt<C>>, Rc<SymbolicExt<C>>),
    Mul(Rc<SymbolicExt<C>>, Rc<SymbolicExt<C>>),
    Sub(Rc<SymbolicExt<C>>, Rc<SymbolicExt<C>>),
    Div(Rc<SymbolicExt<C>>, Rc<SymbolicExt<C>>),
    Neg(Rc<SymbolicExt<C>>),
}

// Implement all arithmetic operations for symbolic Var<C>iables

impl<C: Config> Add for SymbolicVar<C> {
    type Output = SymbolicVar<C>;

    fn add(self, rhs: Self) -> Self::Output {
        SymbolicVar::Add(Rc::new(self), Rc::new(rhs))
    }
}

impl<C: Config> Mul for SymbolicVar<C> {
    type Output = SymbolicVar<C>;

    fn mul(self, rhs: Self) -> Self::Output {
        SymbolicVar::Mul(Rc::new(self), Rc::new(rhs))
    }
}

impl<C: Config> Sub for SymbolicVar<C> {
    type Output = SymbolicVar<C>;

    fn sub(self, rhs: Self) -> Self::Output {
        SymbolicVar::Sub(Rc::new(self), Rc::new(rhs))
    }
}

impl<C: Config> Neg for SymbolicVar<C> {
    type Output = SymbolicVar<C>;

    fn neg(self) -> Self::Output {
        SymbolicVar::Neg(Rc::new(self))
    }
}

impl<C: Config> Add for SymbolicFelt<C> {
    type Output = SymbolicFelt<C>;

    fn add(self, rhs: Self) -> Self::Output {
        SymbolicFelt::Add(Rc::new(self), Rc::new(rhs))
    }
}

impl<C: Config> Mul for SymbolicFelt<C> {
    type Output = SymbolicFelt<C>;

    fn mul(self, rhs: Self) -> Self::Output {
        SymbolicFelt::Mul(Rc::new(self), Rc::new(rhs))
    }
}

impl<C: Config> Sub for SymbolicFelt<C> {
    type Output = SymbolicFelt<C>;

    fn sub(self, rhs: Self) -> Self::Output {
        SymbolicFelt::Sub(Rc::new(self), Rc::new(rhs))
    }
}

impl<C: Config> Div for SymbolicFelt<C> {
    type Output = SymbolicFelt<C>;

    fn div(self, rhs: Self) -> Self::Output {
        SymbolicFelt::Div(Rc::new(self), Rc::new(rhs))
    }
}

impl<C: Config> Neg for SymbolicFelt<C> {
    type Output = SymbolicFelt<C>;

    fn neg(self) -> Self::Output {
        SymbolicFelt::Neg(Rc::new(self))
    }
}

impl<C: Config> Add for SymbolicExt<C> {
    type Output = SymbolicExt<C>;

    fn add(self, rhs: Self) -> Self::Output {
        SymbolicExt::Add(Rc::new(self), Rc::new(rhs))
    }
}

impl<C: Config> Mul for SymbolicExt<C> {
    type Output = SymbolicExt<C>;

    fn mul(self, rhs: Self) -> Self::Output {
        SymbolicExt::Mul(Rc::new(self), Rc::new(rhs))
    }
}

impl<C: Config> Sub for SymbolicExt<C> {
    type Output = SymbolicExt<C>;

    fn sub(self, rhs: Self) -> Self::Output {
        SymbolicExt::Sub(Rc::new(self), Rc::new(rhs))
    }
}

impl<C: Config> Div for SymbolicExt<C> {
    type Output = SymbolicExt<C>;

    fn div(self, rhs: Self) -> Self::Output {
        SymbolicExt::Div(Rc::new(self), Rc::new(rhs))
    }
}

impl<C: Config> Neg for SymbolicExt<C> {
    type Output = SymbolicExt<C>;

    fn neg(self) -> Self::Output {
        SymbolicExt::Neg(Rc::new(self))
    }
}

// Implement all arithmetic operations for concrete Var<C>iables

impl<C: Config> Add<SymbolicVar<C>> for Var<C> {
    type Output = SymbolicVar<C>;

    fn add(self, rhs: SymbolicVar<C>) -> Self::Output {
        SymbolicVar::Add(Rc::new(SymbolicVar::Val(self)), Rc::new(rhs))
    }
}

impl<C: Config> Mul<SymbolicVar<C>> for Var<C> {
    type Output = SymbolicVar<C>;

    fn mul(self, rhs: SymbolicVar<C>) -> Self::Output {
        SymbolicVar::Mul(Rc::new(SymbolicVar::Val(self)), Rc::new(rhs))
    }
}

impl<C: Config> Sub<SymbolicVar<C>> for Var<C> {
    type Output = SymbolicVar<C>;

    fn sub(self, rhs: SymbolicVar<C>) -> Self::Output {
        SymbolicVar::Sub(Rc::new(SymbolicVar::Val(self)), Rc::new(rhs))
    }
}

impl<C: Config> Add<SymbolicFelt<C>> for Felt<C> {
    type Output = SymbolicFelt<C>;

    fn add(self, rhs: SymbolicFelt<C>) -> Self::Output {
        SymbolicFelt::Add(Rc::new(SymbolicFelt::Val(self)), Rc::new(rhs))
    }
}

impl<C: Config> Mul<SymbolicFelt<C>> for Felt<C> {
    type Output = SymbolicFelt<C>;

    fn mul(self, rhs: SymbolicFelt<C>) -> Self::Output {
        SymbolicFelt::Mul(Rc::new(SymbolicFelt::Val(self)), Rc::new(rhs))
    }
}

impl<C: Config> Sub<SymbolicFelt<C>> for Felt<C> {
    type Output = SymbolicFelt<C>;

    fn sub(self, rhs: SymbolicFelt<C>) -> Self::Output {
        SymbolicFelt::Sub(Rc::new(SymbolicFelt::Val(self)), Rc::new(rhs))
    }
}

impl<C: Config> Div<SymbolicFelt<C>> for Felt<C> {
    type Output = SymbolicFelt<C>;

    fn div(self, rhs: SymbolicFelt<C>) -> Self::Output {
        SymbolicFelt::Div(Rc::new(SymbolicFelt::Val(self)), Rc::new(rhs))
    }
}

impl<C: Config> Add<SymbolicExt<C>> for Ext<C> {
    type Output = SymbolicExt<C>;

    fn add(self, rhs: SymbolicExt<C>) -> Self::Output {
        SymbolicExt::Add(Rc::new(SymbolicExt::Val(self)), Rc::new(rhs))
    }
}

impl<C: Config> Mul<SymbolicExt<C>> for Ext<C> {
    type Output = SymbolicExt<C>;

    fn mul(self, rhs: SymbolicExt<C>) -> Self::Output {
        SymbolicExt::Mul(Rc::new(SymbolicExt::Val(self)), Rc::new(rhs))
    }
}

impl<C: Config> Sub<SymbolicExt<C>> for Ext<C> {
    type Output = SymbolicExt<C>;

    fn sub(self, rhs: SymbolicExt<C>) -> Self::Output {
        SymbolicExt::Sub(Rc::new(SymbolicExt::Val(self)), Rc::new(rhs))
    }
}

impl<C: Config> Div<SymbolicExt<C>> for Ext<C> {
    type Output = SymbolicExt<C>;

    fn div(self, rhs: SymbolicExt<C>) -> Self::Output {
        SymbolicExt::Div(Rc::new(SymbolicExt::Val(self)), Rc::new(rhs))
    }
}

// Implement operations for Var<C>iables themselves

impl<C: Config> Add for Var<C> {
    type Output = SymbolicVar<C>;

    fn add(self, rhs: Self) -> Self::Output {
        SymbolicVar::Add(
            Rc::new(SymbolicVar::Val(self)),
            Rc::new(SymbolicVar::Val(rhs)),
        )
    }
}

impl<C: Config> Mul for Var<C> {
    type Output = SymbolicVar<C>;

    fn mul(self, rhs: Self) -> Self::Output {
        SymbolicVar::Mul(
            Rc::new(SymbolicVar::Val(self)),
            Rc::new(SymbolicVar::Val(rhs)),
        )
    }
}
