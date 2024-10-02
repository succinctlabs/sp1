use std::iter::repeat;

use p3_field::PrimeField64;
use vec_map::{Entry, VecMap};

use crate::{air::Block, Address};

#[derive(Debug, Clone, Default)]
pub struct MemoryEntry<F> {
    pub val: Block<F>,
    pub mult: F,
}

pub trait Memory<F> {
    /// Allocates memory with at least the given capacity.
    fn with_capacity(capacity: usize) -> Self;

    /// Read from a memory address. Decrements the memory entry's mult count.
    ///
    /// # Panics
    /// Panics if the address is unassigned.
    fn mr(&mut self, addr: Address<F>) -> &mut MemoryEntry<F>;

    /// Read from a memory address. Reduces the memory entry's mult count by the given amount.
    ///
    /// # Panics
    /// Panics if the address is unassigned.
    fn mr_mult(&mut self, addr: Address<F>, mult: F) -> &mut MemoryEntry<F>;

    /// Write to a memory address, setting the given value and mult.
    ///
    /// # Panics
    /// Panics if the address is already assigned.
    fn mw(&mut self, addr: Address<F>, val: Block<F>, mult: F) -> &mut MemoryEntry<F>;
}

#[derive(Clone, Debug, Default)]
pub struct MemVecMap<F>(pub VecMap<MemoryEntry<F>>);

impl<F: PrimeField64> Memory<F> for MemVecMap<F> {
    fn with_capacity(capacity: usize) -> Self {
        Self(VecMap::with_capacity(capacity))
    }

    fn mr(&mut self, addr: Address<F>) -> &mut MemoryEntry<F> {
        self.mr_mult(addr, F::one())
    }

    fn mr_mult(&mut self, addr: Address<F>, mult: F) -> &mut MemoryEntry<F> {
        match self.0.entry(addr.as_usize()) {
            Entry::Occupied(mut entry) => {
                let entry_mult = &mut entry.get_mut().mult;
                *entry_mult -= mult;
                entry.into_mut()
            }
            Entry::Vacant(_) => panic!("tried to read from unassigned address: {addr:?}",),
        }
    }

    fn mw(&mut self, addr: Address<F>, val: Block<F>, mult: F) -> &mut MemoryEntry<F> {
        let index = addr.as_usize();
        match self.0.entry(index) {
            Entry::Occupied(entry) => {
                panic!("tried to write to assigned address {}: {:?}", index, entry.get())
            }
            Entry::Vacant(entry) => entry.insert(MemoryEntry { val, mult }),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemVec<F>(pub Vec<Option<MemoryEntry<F>>>);

impl<F: PrimeField64> Memory<F> for MemVec<F> {
    fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    fn mr(&mut self, addr: Address<F>) -> &mut MemoryEntry<F> {
        self.mr_mult(addr, F::one())
    }

    fn mr_mult(&mut self, addr: Address<F>, mult: F) -> &mut MemoryEntry<F> {
        match self.0.get_mut(addr.as_usize()) {
            Some(Some(entry)) => {
                entry.mult -= mult;
                entry
            }
            _ => panic!(
                "tried to read from unassigned address: {addr:?}\nbacktrace: {:?}",
                backtrace::Backtrace::new()
            ),
        }
    }

    fn mw(&mut self, addr: Address<F>, val: Block<F>, mult: F) -> &mut MemoryEntry<F> {
        let addr_usize = addr.as_usize();
        self.0.extend(repeat(None).take((addr_usize + 1).saturating_sub(self.0.len())));
        match &mut self.0[addr_usize] {
            Some(entry) => panic!(
                "tried to write to assigned address: {entry:?}\nbacktrace: {:?}",
                backtrace::Backtrace::new()
            ),
            entry @ None => entry.insert(MemoryEntry { val, mult }),
        }
    }
}
