use p3_air::BaseAir;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::runtime::ExecutionRecord;

pub trait MachineAir<F: Field>: BaseAir<F> {
    fn name(&self) -> String;

    fn generate_trace(&self, record: &mut ExecutionRecord) -> RowMajorMatrix<F>;

    fn shard(&self, input: &ExecutionRecord, outputs: &mut Vec<ExecutionRecord>);

    fn include(&self, record: &ExecutionRecord) -> bool;
}
