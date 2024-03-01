use std::fmt::{Display, Formatter};

use crate::runtime::{ExecutionRecord, SyscallCode};
use crate::syscall::precompiles::{MemoryReadRecord, MemoryWriteRecord};

mod air;
mod syscall;
mod trace;

pub use air::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
#[derive(Clone, Debug)]
pub struct NativeEvent {
    pub clk: u32,
    pub shard: u32,

    a_record: MemoryWriteRecord,
    b_record: MemoryReadRecord,
}

impl BinaryOpcode {
    pub(crate) fn events<'b>(&self, input: &'b ExecutionRecord) -> &'b [NativeEvent] {
        match self {
            Self::Add => &input.native_add_events,
            Self::Mul => &input.native_mul_events,
            Self::Sub => &input.native_sub_events,
            Self::Div => &input.native_div_events,
        }
    }

    pub(crate) fn events_mut<'b>(
        &self,
        input: &'b mut ExecutionRecord,
    ) -> &'b mut Vec<NativeEvent> {
        match self {
            Self::Add => &mut input.native_add_events,
            Self::Mul => &mut input.native_mul_events,
            Self::Sub => &mut input.native_sub_events,
            Self::Div => &mut input.native_div_events,
        }
    }
}

impl Display for BinaryOpcode {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        match self {
            Self::Add => write!(f, "add"),
            Self::Mul => write!(f, "mul"),
            Self::Sub => write!(f, "sub"),
            Self::Div => write!(f, "div"),
        }
    }
}
