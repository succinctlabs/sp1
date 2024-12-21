use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub enum BaseAluOpcode {
    AddF,
    SubF,
    MulF,
    DivF,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub enum ExtAluOpcode {
    AddE,
    SubE,
    MulE,
    DivE,
}
