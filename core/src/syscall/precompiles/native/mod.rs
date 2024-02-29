use crate::runtime::SyscallCode;
use crate::syscall::precompiles::{MemoryReadRecord, MemoryWriteRecord};

mod air;

pub use air::*;

pub enum BinaryOpcode {
    Add = SyscallCode::FADD as isize,
    Mul = SyscallCode::FMUL as isize,
    Sub = SyscallCode::FSUB as isize,
    Div = SyscallCode::FDIV as isize,
}

/// An arithmetic binary operation in the air native field.
///
/// The event descrives a request for `Op(a, b) -> a` where `Op` is an arithmetic binary operation,
/// `b` and `c` are the input operands, and `a` is the output. The supported operations are:
/// `add`, `mul`, `sub`, `div`.
pub struct NativeEvent {
    pub clk: u32,
    pub shard: u32,

    op: BinaryOpcode,

    a_record: MemoryWriteRecord,
    b_record: MemoryReadRecord,
}
