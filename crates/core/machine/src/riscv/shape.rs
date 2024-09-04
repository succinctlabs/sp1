use hashbrown::HashMap;
use p3_field::PrimeField32;
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_stark::air::MachineAir;

use super::RiscvAir;

/// A structure that enables fixing the shape of an executionrecord.
pub struct CoreShapeConfig<F: PrimeField32> {
    pub allowed_heights: HashMap<RiscvAir<F>, Vec<usize>>,
}

impl<F: PrimeField32> CoreShapeConfig<F> {
    /// Fix the preprocessed shape of the proof.
    pub fn fix_preprocessed_shape(&self, program: &mut Program) {
        if program.preprocessed_shape.is_some() {
            tracing::warn!("preprocessed shape already fixed");
            // TODO: Change this to not panic (i.e. return);
            panic!("cannot fix preprocessed shape twice");
        }
    }

    /// Fix the shape of the proof.
    pub fn fix_shape(&self, record: &mut ExecutionRecord) {
        if record.shape.is_some() {
            tracing::warn!("shape already fixed");
            // TODO: Change this to not panic (i.e. return);
            panic!("cannot fix shape twice");
        }
    }
}
