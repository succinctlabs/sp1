use crate::program::ISA;

pub enum ALUOperation {
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

pub struct ALU<IS: ISA> {
    op: ALUOperation,
    operands: [IS::Word; 3],
    values: [IS::Word; 3],
}
