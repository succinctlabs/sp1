use std::collections::BTreeMap;

use p3_field::PrimeField32;
use serde::{Deserialize, Serialize};

use super::RangeCheckOpcode;

/// A byte lookup event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RangeCheckEvent {
    /// The opcode of the operation.
    pub opcode: RangeCheckOpcode,

    /// The val to range check.
    pub val: u16,
}
