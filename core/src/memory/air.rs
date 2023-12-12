use crate::air::{Bool, Word};

/// An AIR table for memory accesses.
#[derive(Debug, Clone)]
pub struct MemoryAir<T> {
    /// The clock cycle value for this memory access.
    pub clk: T,
    /// The address of the memory access.
    pub addr: T,
    /// The value being read from or written to memory.
    pub value: Word<T>,

    /// Whether the memory is being read from or written to.
    pub is_read: Bool<T>,
    /// Whether the memory has been initialized.
    pub is_init: Bool<T>,
}
