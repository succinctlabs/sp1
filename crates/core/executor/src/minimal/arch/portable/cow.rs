use crate::{
    memory::{Entry, PagedMemory, MAX_LOG_ADDR},
    ExecutionError, Opcode,
};
use std::cell::RefCell;

/// A memory backed by [`PagedMemory`], which can be in either owned or COW mode.
pub enum MaybeCowMemory<T: Copy> {
    Cow { copy: PagedMemory<T>, original: PagedMemory<T> },
    Owned { memory: PagedMemory<T> },
}

impl<T: Copy> MaybeCowMemory<T> {
    /// Create a new owned memory.
    pub fn new_owned() -> Self {
        Self::Owned { memory: PagedMemory::default() }
    }

    /// Create a new cow memory.
    pub fn new_cow(original: PagedMemory<T>) -> Self {
        Self::Cow { copy: PagedMemory::default(), original }
    }

    /// Initialize the cow memory.
    ///
    /// If the memory is already in COW mode, this is a no-op.
    pub fn copy_on_write(&mut self) {
        match self {
            Self::Cow { .. } => {}
            Self::Owned { memory } => {
                *self = Self::new_cow(std::mem::take(memory));
            }
        }
    }

    /// Convert the memory to owned mode, discarding any of the memory in the COW.
    pub fn owned(&mut self) {
        match self {
            Self::Cow { copy: _, original } => {
                *self = Self::Owned { memory: std::mem::take(original) };
            }
            Self::Owned { .. } => {}
        }
    }

    /// Get a value from the memory.
    pub fn get(&self, addr: u64) -> Option<&T> {
        assert!(addr.is_multiple_of(8), "Address must be a multiple of 8");

        match self {
            Self::Cow { copy, original } => copy.get(addr).or_else(|| original.get(addr)),
            Self::Owned { memory } => memory.get(addr),
        }
    }

    /// Get an entry for the given address.
    pub fn entry(&mut self, addr: u64) -> (Entry<'_, T>, bool) {
        assert!(addr.is_multiple_of(8), "Address must be a multiple of 8");

        let mut duplicated = false;
        // First we ensure that the copy has the value, if it exisits in the original.
        match self {
            Self::Cow { copy, original } => match copy.entry(addr) {
                Entry::Vacant(entry) => {
                    if let Some(value) = original.get(addr) {
                        entry.insert(*value);
                        duplicated = true;
                    }
                }
                Entry::Occupied(_) => {}
            },
            Self::Owned { .. } => {}
        }

        (
            match self {
                Self::Cow { copy, original: _ } => copy.entry(addr),
                Self::Owned { memory } => memory.entry(addr),
            },
            duplicated,
        )
    }

    /// Insert a value into the memory.
    pub fn insert(&mut self, addr: u64, value: T) -> Option<T> {
        assert!(addr.is_multiple_of(8), "Address must be a multiple of 8");

        match self {
            Self::Cow { copy, original: _ } => copy.insert(addr, value),
            Self::Owned { memory } => memory.insert(addr, value),
        }
    }
}

#[derive(Clone)]
enum Limiter {
    NoLimit,
    Limit { current: usize, limit: usize },
}

impl Limiter {
    fn new(memory_limit: Option<u64>) -> Self {
        match memory_limit {
            // Convert memory limit from bytes to entries
            Some(memory_limit) => Self::Limit { current: 0, limit: (memory_limit / 8) as usize },
            None => Self::NoLimit,
        }
    }

    /// Increate used entries by 1.
    fn increase(&mut self) -> Result<(), ExecutionError> {
        if let Self::Limit { current, limit } = self {
            *current += 1;
            if current > limit {
                return Err(ExecutionError::TooMuchMemory());
            }
        }
        Ok(())
    }

    fn check_ptr(&self, addr: u64, write: bool) -> Result<(), ExecutionError> {
        // Memory bound checking does not rely on values of memory limit.
        // Nonetheless we do bound checking only when memory limit is present.
        // This is to keep the old behavior of the portable executor unchanged.
        if let Self::Limit { .. } = self {
            let max_memory = 1u64 << MAX_LOG_ADDR;
            if addr > max_memory - 8 {
                return Err(ExecutionError::InvalidMemoryAccess(
                    if write { Opcode::SD } else { Opcode::LD },
                    addr,
                ));
            }
        }
        Ok(())
    }
}

/// A memory with an optional entry limit
pub struct LimitedMemory<T: Copy> {
    memory: MaybeCowMemory<T>,
    limiter: Limiter,
    before_cow: Option<Limiter>,
    // Last memory access error
    last_error: RefCell<Option<ExecutionError>>,
    // When last error exists, all read / write operation will be
    // redirected to this dummy value.
    dummy_value: T,
}

fn c(last_error: &RefCell<Option<ExecutionError>>, result: Result<(), ExecutionError>) {
    let mut e = last_error.try_borrow_mut().expect("borrow twice");
    if e.is_none() {
        *e = result.err();
    }
}

impl<T: Copy + Default> LimitedMemory<T> {
    /// Create a new owned, limited memory. Accepts an optional memory size limit in bytes.
    pub fn new_owned(memory_limit: Option<u64>) -> Self {
        Self {
            memory: MaybeCowMemory::new_owned(),
            limiter: Limiter::new(memory_limit),
            before_cow: None,
            last_error: None.into(),
            dummy_value: T::default(),
        }
    }

    /// Initialize the cow memory.
    ///
    /// If the memory is already in COW mode, this is a no-op.
    #[inline]
    pub fn copy_on_write(&mut self) {
        self.memory.copy_on_write();
        self.before_cow = Some(self.limiter.clone());
    }

    /// Convert the memory to owned mode, discarding any of the memory in the COW.
    pub fn owned(&mut self) {
        self.memory.owned();
        self.limiter = self.before_cow.take().unwrap();
    }

    /// Get a value from the memory.
    #[inline]
    pub fn get(&self, addr: u64) -> Option<&T> {
        self.check_ptr(addr, false);
        if self.has_last_error() {
            return Some(&self.dummy_value);
        }
        // Getting a memory needs no limitation checks
        self.memory.get(addr)
    }

    /// Insert a value into the memory.
    #[inline]
    pub fn insert(&mut self, addr: u64, value: T) {
        self.check_ptr(addr, true);
        if self.has_last_error() {
            return;
        }
        let previous_value = self.memory.insert(addr, value);
        if previous_value.is_none() {
            c(&self.last_error, self.limiter.increase());
        }
    }

    #[inline]
    fn check_ptr(&self, addr: u64, write: bool) {
        c(&self.last_error, self.limiter.check_ptr(addr, write));
    }

    #[inline]
    /// Returns true if last error is set
    pub fn has_last_error(&self) -> bool {
        self.last_error.borrow().is_some()
    }

    /// Returns last error
    ///
    /// # Safety
    /// This method panics when last error is not set
    #[inline]
    pub fn last_error(&self) -> ExecutionError {
        self.last_error.borrow().clone().unwrap()
    }
}

impl<T: Copy + Default> LimitedMemory<T> {
    /// Get a mutable reference for the given address
    #[inline]
    pub fn get_mut(&mut self, addr: u64) -> &'_ mut T {
        self.check_ptr(addr, true);
        if self.has_last_error() {
            return &mut self.dummy_value;
        }
        let (entry, duplicated) = self.memory.entry(addr);
        if duplicated || matches!(entry, Entry::Vacant(_)) {
            c(&self.last_error, self.limiter.increase());
        }
        entry.or_default()
    }
}
