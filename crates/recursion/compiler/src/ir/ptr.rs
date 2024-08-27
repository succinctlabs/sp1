use core::ops::{Add, Sub};

use p3_field::Field;

use super::{Builder, Config, DslIr, MemIndex, MemVariable, SymbolicVar, Usize, Var, Variable};

/// A point to a location in memory.
#[derive(Debug, Clone, Copy)]
pub struct Ptr<N> {
    pub address: Var<N>,
}

pub struct SymbolicPtr<N: Field> {
    pub address: SymbolicVar<N>,
}

impl<C: Config> Builder<C> {
    /// Allocates an array on the heap.
    pub(crate) fn alloc(&mut self, len: Usize<C::N>, size: usize) -> Ptr<C::N> {
        let ptr = Ptr::uninit(self);
        self.push_op(DslIr::Alloc(ptr, len, size));
        ptr
    }

    /// Loads a value from memory.
    pub fn load<V: MemVariable<C>>(&mut self, var: V, ptr: Ptr<C::N>, index: MemIndex<C::N>) {
        var.load(ptr, index, self);
    }

    /// Stores a value to memory.
    pub fn store<V: MemVariable<C>>(&mut self, ptr: Ptr<C::N>, index: MemIndex<C::N>, value: V) {
        value.store(ptr, index, self);
    }
}

impl<C: Config> Variable<C> for Ptr<C::N> {
    type Expression = SymbolicPtr<C::N>;

    fn uninit(builder: &mut Builder<C>) -> Self {
        Ptr { address: Var::uninit(builder) }
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        self.address.assign(src.address, builder);
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        Var::assert_eq(lhs.into().address, rhs.into().address, builder);
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        Var::assert_ne(lhs.into().address, rhs.into().address, builder);
    }
}

impl<C: Config> MemVariable<C> for Ptr<C::N> {
    fn size_of() -> usize {
        1
    }

    fn load(&self, ptr: Ptr<C::N>, index: MemIndex<C::N>, builder: &mut Builder<C>) {
        self.address.load(ptr, index, builder);
    }

    fn store(&self, ptr: Ptr<<C as Config>::N>, index: MemIndex<C::N>, builder: &mut Builder<C>) {
        self.address.store(ptr, index, builder);
    }
}

impl<N: Field> From<Ptr<N>> for SymbolicPtr<N> {
    fn from(ptr: Ptr<N>) -> Self {
        SymbolicPtr { address: SymbolicVar::from(ptr.address) }
    }
}

impl<N: Field> Add for Ptr<N> {
    type Output = SymbolicPtr<N>;

    fn add(self, rhs: Self) -> Self::Output {
        SymbolicPtr { address: self.address + rhs.address }
    }
}

impl<N: Field> Sub for Ptr<N> {
    type Output = SymbolicPtr<N>;

    fn sub(self, rhs: Self) -> Self::Output {
        SymbolicPtr { address: self.address - rhs.address }
    }
}

impl<N: Field> Add for SymbolicPtr<N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self { address: self.address + rhs.address }
    }
}

impl<N: Field> Sub for SymbolicPtr<N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self { address: self.address - rhs.address }
    }
}

impl<N: Field> Add<Ptr<N>> for SymbolicPtr<N> {
    type Output = Self;

    fn add(self, rhs: Ptr<N>) -> Self {
        Self { address: self.address + rhs.address }
    }
}

impl<N: Field> Sub<Ptr<N>> for SymbolicPtr<N> {
    type Output = Self;

    fn sub(self, rhs: Ptr<N>) -> Self {
        Self { address: self.address - rhs.address }
    }
}

impl<N: Field> Add<SymbolicPtr<N>> for Ptr<N> {
    type Output = SymbolicPtr<N>;

    fn add(self, rhs: SymbolicPtr<N>) -> SymbolicPtr<N> {
        SymbolicPtr { address: self.address + rhs.address }
    }
}

impl<N: Field> Add<SymbolicVar<N>> for Ptr<N> {
    type Output = SymbolicPtr<N>;

    fn add(self, rhs: SymbolicVar<N>) -> SymbolicPtr<N> {
        SymbolicPtr { address: self.address + rhs }
    }
}

impl<N: Field> Sub<SymbolicVar<N>> for Ptr<N> {
    type Output = SymbolicPtr<N>;

    fn sub(self, rhs: SymbolicVar<N>) -> SymbolicPtr<N> {
        SymbolicPtr { address: self.address - rhs }
    }
}

impl<N: Field> Sub<SymbolicPtr<N>> for Ptr<N> {
    type Output = SymbolicPtr<N>;

    fn sub(self, rhs: SymbolicPtr<N>) -> SymbolicPtr<N> {
        SymbolicPtr { address: self.address - rhs.address }
    }
}

impl<N: Field> Add<Usize<N>> for Ptr<N> {
    type Output = SymbolicPtr<N>;

    fn add(self, rhs: Usize<N>) -> SymbolicPtr<N> {
        match rhs {
            Usize::Const(rhs) => {
                SymbolicPtr { address: self.address + N::from_canonical_usize(rhs) }
            }
            Usize::Var(rhs) => SymbolicPtr { address: self.address + rhs },
        }
    }
}

impl<N: Field> Add<Usize<N>> for SymbolicPtr<N> {
    type Output = SymbolicPtr<N>;

    fn add(self, rhs: Usize<N>) -> SymbolicPtr<N> {
        match rhs {
            Usize::Const(rhs) => {
                SymbolicPtr { address: self.address + N::from_canonical_usize(rhs) }
            }
            Usize::Var(rhs) => SymbolicPtr { address: self.address + rhs },
        }
    }
}

impl<N: Field> Sub<Usize<N>> for Ptr<N> {
    type Output = SymbolicPtr<N>;

    fn sub(self, rhs: Usize<N>) -> SymbolicPtr<N> {
        match rhs {
            Usize::Const(rhs) => {
                SymbolicPtr { address: self.address - N::from_canonical_usize(rhs) }
            }
            Usize::Var(rhs) => SymbolicPtr { address: self.address - rhs },
        }
    }
}

impl<N: Field> Sub<Usize<N>> for SymbolicPtr<N> {
    type Output = SymbolicPtr<N>;

    fn sub(self, rhs: Usize<N>) -> SymbolicPtr<N> {
        match rhs {
            Usize::Const(rhs) => {
                SymbolicPtr { address: self.address - N::from_canonical_usize(rhs) }
            }
            Usize::Var(rhs) => SymbolicPtr { address: self.address - rhs },
        }
    }
}
