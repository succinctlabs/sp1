use std::{
    cell::UnsafeCell,
    mem::{self, MaybeUninit},
};

use p3_field::PrimeField64;

use crate::{air::Block, Address};

#[derive(Debug, Clone, Default, Copy)]
pub struct MemoryEntry<F> {
    pub val: Block<F>,
}

/// `UnsafeCell`, but `Sync`.
///
/// A replication of the standard library type `SyncUnsafeCell`, still unstable as of Rust 1.81.0.
#[derive(Debug, Default)]
#[repr(transparent)]
struct SyncUnsafeCell<T: ?Sized>(UnsafeCell<T>);

unsafe impl<T: ?Sized + Sync> Sync for SyncUnsafeCell<T> {}

#[derive(Debug, Default)]
pub struct MemVec<F>(Vec<SyncUnsafeCell<MaybeUninit<MemoryEntry<F>>>>);

impl<F: PrimeField64> MemVec<F> {
    pub fn with_capacity(capacity: usize) -> Self {
        // SAFETY: SyncUnsafeCell is a `repr(transparent)` newtype of `UnsafeCell`, which has
        // the same representation as its inner type.
        Self(unsafe {
            mem::transmute::<
                Vec<MaybeUninit<MemoryEntry<F>>>,
                Vec<SyncUnsafeCell<MaybeUninit<MemoryEntry<F>>>>,
            >(vec![MaybeUninit::uninit(); capacity])
        })
    }

    pub fn mr(&mut self, addr: Address<F>) -> &MemoryEntry<F> {
        // SAFETY: We have exclusive access to the memory, so no data races can occur.
        unsafe { self.mr_unchecked(addr) }
    }

    /// # Safety
    /// This should be called precisely when memory is to be read according to a happens-before
    /// relation corresponding to the documented invariants of [`crate::RecursionProgram`]
    /// invariants. This guarantees the absence of any data races.
    pub unsafe fn mr_unchecked(&self, addr: Address<F>) -> &MemoryEntry<F> {
        match self.0.get(addr.as_usize()).map(|c| unsafe {
            // SAFETY: The pointer is dereferenceable. It has already been written to due to the
            // happens-before relation (in `mw_unchecked`), so no mutable/unique reference can
            // exist. The immutable/shared reference returned indeed remains valid as
            // long as the lifetime of `&self` (lifetimes are elided) since it refers to
            // memory directly owned by `self`.
            &*c.0.get()
        }) {
            Some(entry) => unsafe {
                // SAFETY: It has already been written to, so the value is valid. The reference
                // obeys both lifetime and aliasing rules, as discussed above.
                entry.assume_init_ref()
            },
            None => panic!(
                "expected address {} to be less than length {}",
                addr.as_usize(),
                self.0.len()
            ),
        }
    }

    pub fn mw(&mut self, addr: Address<F>, val: Block<F>) {
        // SAFETY: We have exclusive access to the memory, so no data races can occur.
        // Leaks may occur if the same address is written to twice, unless `F` is trivially
        // destructible (which is the case if it is merely a number).
        unsafe { self.mw_unchecked(addr, val) }
    }

    /// # Safety
    /// This should be called precisely when memory is to be written according to a happens-before
    /// relation corresponding to the documented invariants of [`crate::RecursionProgram`]
    /// invariants. This guarantees the absence of any data races.
    pub unsafe fn mw_unchecked(&self, addr: Address<F>, val: Block<F>) {
        match self.0.get(addr.as_usize()).map(|c| unsafe {
            // SAFETY: The pointer is dereferenceable. There are no other aliases to the data
            // because of the happens-before relation (no other `mw_unchecked` can be invoked on
            // the same address, and this call happens-before any `mr_unchecked`.)
            // The mutable/shared reference is dropped below, so it does not escape with
            // an invalid lifetime.
            &mut *c.0.get()
        }) {
            // This does not leak memory because the address is written to exactly once.
            // Leaking is memory-safe in Rust, so this isn't technically a "SAFETY" comment.
            Some(entry) => drop(entry.write(MemoryEntry { val })),
            None => panic!(
                "expected address {} to be less than length {}",
                addr.as_usize(),
                self.0.len()
            ),
        }
    }
}
