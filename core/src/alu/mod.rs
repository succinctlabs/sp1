use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AluOperation {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    Leq,
}

/// The state of the Alu at a particular point in the program execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Alu {
    pub op: AluOperation,
    pub v_a: u32,
    pub v_b: u32,
    pub v_c: u32,
}
