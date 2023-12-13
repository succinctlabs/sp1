pub mod opcode;
pub mod runtime;
pub mod instruction;

use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
    mem,
};

use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    alu::{add::AddChip, bitwise::BitwiseChip, sub::SubChip, AluEvent},
    cpu::{trace::CpuChip, CpuEvent},
    memory::{MemOp, MemoryEvent},
    program::ProgramChip,
    utils::Chip,
};