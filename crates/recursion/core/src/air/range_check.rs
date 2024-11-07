use p3_field::Field;
use serde::{Deserialize, Serialize};

/// The number of different range check operations.
pub const NUM_RANGE_CHECK_OPS: usize = 2;

/// A byte opcode which the chip can process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RangeCheckOpcode {
    /// U12 range check
    U12 = 0,

    /// U16 range check
    U16 = 1,
}

impl RangeCheckOpcode {
    /// Get all the range check opcodes.
    pub fn all() -> Vec<Self> {
        let opcodes = vec![RangeCheckOpcode::U12, RangeCheckOpcode::U16];
        assert_eq!(opcodes.len(), NUM_RANGE_CHECK_OPS);
        opcodes
    }

    /// Convert the opcode to a field element.
    pub fn as_field<F: Field>(self) -> F {
        F::from_canonical_u8(self as u8)
    }
}
