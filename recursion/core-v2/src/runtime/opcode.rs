use p3_field::AbstractField;
use serde::{Deserialize, Serialize};

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Opcode {
    AddF,
    SubF,
    MulF,
    DivF,
    AddE,
    SubE,
    MulE,
    DivE,
    Poseidon2,
}

impl Opcode {
    pub fn as_field<F: AbstractField>(&self) -> F {
        F::from_canonical_u32(*self as u32)
    }
}
