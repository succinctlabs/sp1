use p3_air::AirBuilder;

use crate::air::{AirConstraint, AirVariable, Bool, Word};

#[derive(Debug, Clone, Copy)]
pub struct MemoryAir;

/// An AIR table for memory accesses.
#[derive(Debug, Clone)]
pub struct MemoryCols<T> {
    /// The clock cycle value for this memory access.
    pub clk: T,
    /// The address of the memory access.
    pub addr: Word<T>,
    /// The value being read from or written to memory.
    pub value: Word<T>,
    /// Whether the memory is being read from or written to.
    pub is_read: Bool<T>,
    /// Whether the memory has been initialized.
    pub is_init: Bool<T>,
    /// Low 16-bits of the difference between two consecutive addresses or clock cycles.
    pub diff_low: T,
    /// High 16-bits of the difference between two consecutive addresses or clock cycles.
    pub diff_high: T,
    /// The carry bit of the difference between two consecutive addresses or clock cycles.
    pub diff_carry: T,
    /// An auxiliary value used to hold 1 / (addr - prev_addr) when the address changes and set to
    /// zero when the address does not change.
    pub temp: T,
}

impl<AB: AirBuilder> AirConstraint<AB> for MemoryCols<AB::Var> {
    fn eval(&self, builder: &mut AB) {
        // Assert that the booleans are either 0 or 1.
        // REMARK: This might get automated.
        self.is_read.eval_is_valid(builder);
        self.is_init.eval_is_valid(builder);

        // Assert that the value is zero when the memory is not initialized.
    }
}
