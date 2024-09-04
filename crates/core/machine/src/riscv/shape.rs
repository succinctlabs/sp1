use hashbrown::HashMap;
use p3_field::PrimeField32;
use sp1_core_executor::{CoreShape, ExecutionRecord, Program};
use sp1_stark::air::MachineAir;

use super::RiscvAir;

/// A structure that enables fixing the shape of an executionrecord.
pub struct CoreShapeConfig<F: PrimeField32> {
    allowed_heights: HashMap<RiscvAir<F>, Vec<usize>>,
}

impl<F: PrimeField32> CoreShapeConfig<F> {
    /// Fix the preprocessed shape of the proof.
    pub fn fix_preprocessed_shape(&self, program: &mut Program) {
        if program.preprocessed_shape.is_some() {
            tracing::warn!("preprocessed shape already fixed");
            // TODO: Change this to not panic (i.e. return);
            panic!("cannot fix preprocessed shape twice");
        }

        let shape = RiscvAir::<F>::preprocessed_heights(program)
            .into_iter()
            .map(|(air, height)| {
                for &allowed in self.allowed_heights.get(&air).unwrap() {
                    if height <= allowed {
                        return (air.name(), allowed);
                    }
                }
                panic!("air {} not allowed at height {}", air.name(), height);
            })
            .collect();

        let shape = CoreShape { inner: shape };
        program.preprocessed_shape = Some(shape);
    }

    /// Fix the shape of the proof.
    pub fn fix_shape(&self, record: &mut ExecutionRecord) {
        if record.shape.is_some() {
            tracing::warn!("shape already fixed");
            // TODO: Change this to not panic (i.e. return);
            panic!("cannot fix shape twice");
        }

        let shape = RiscvAir::<F>::heights(record)
            .into_iter()
            .map(|(air, height)| {
                for &allowed in self.allowed_heights.get(&air).unwrap() {
                    if height <= allowed {
                        return (air.name(), allowed);
                    }
                }
                panic!("air {} not allowed at height {}", air.name(), height);
            })
            .collect();

        let shape = CoreShape { inner: shape };
        record.shape = Some(shape);
    }
}

// impl<F: PrimeField32> Default for CoreShapeConfig<F> {
//     fn default() -> Self {
//         let mut allowed_heights = HashMap::new();
//     }
// }
