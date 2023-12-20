use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::{runtime::Runtime, utils::Chip};

pub mod air;
mod trace;

pub enum MemoryStateChip {
    Output,
    Input,
}

impl<F: Field> Chip<F> for MemoryStateChip {
    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F> {
        match self {
            MemoryStateChip::Output => Self::generate_trace_output(runtime),
            MemoryStateChip::Input => todo!(),
        }
    }
}
