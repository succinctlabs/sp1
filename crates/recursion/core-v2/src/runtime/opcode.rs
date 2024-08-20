use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BaseAluOpcode {
    AddF,
    SubF,
    MulF,
    DivF,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExtAluOpcode {
    AddE,
    SubE,
    MulE,
    DivE,
}
