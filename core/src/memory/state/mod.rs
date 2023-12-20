pub mod air;
mod trace;

use std::borrow::Borrow;

use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::{dense::RowMajorMatrix, MatrixRowSlices};

use p3_field::AbstractField;

use crate::{air::CurtaAirBuilder, runtime::Runtime, utils::Chip};

use self::air::{MemoryStateCols, NUM_MEMORY_STATE_COLS};

pub enum MemoryStateChip {
    Output,
    Input,
}

impl<F: Field> BaseAir<F> for MemoryStateChip {
    fn width(&self) -> usize {
        NUM_MEMORY_STATE_COLS
    }
}

impl<AB: CurtaAirBuilder> Air<AB> for MemoryStateChip {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &MemoryStateCols<AB::Var> = main.row_slice(0).borrow();
        builder.send_memory(
            local.clk,
            local.addr,
            local.value,
            local.is_read.0,
            AB::F::one(),
        );
    }
}

// impl<F: Field> Chip<F> for MemoryStateChip {
//     fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F> {
//         let last_writes = runtime.last_memory_events;
//     }
// }
