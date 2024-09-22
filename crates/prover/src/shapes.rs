use std::sync::Arc;

use p3_baby_bear::BabyBear;
use sp1_core_machine::riscv::{CoreShapeConfig, ShaCompressChip};
use sp1_recursion_circuit_v2::machine::{
    SP1CompressWithVKeyWitnessValues, SP1CompressWithVkeyShape, SP1DeferredShape,
    SP1DeferredWitnessValues, SP1RecursionShape, SP1RecursionWitnessValues,
};
use sp1_recursion_core_v2::{shape::RecursionShapeConfig, RecursionProgram};
use sp1_stark::{MachineProver, ProofShape};

use crate::{components::SP1ProverComponents, CompressAir, SP1Prover};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SP1ProofShape {
    Recursion(ProofShape),
    Compress(Vec<ProofShape>),
    Deferred(ProofShape),
}

pub enum SP1CompressProgramShape {
    Recursion(SP1RecursionShape),
    Compress(SP1CompressWithVkeyShape),
    Deferred(SP1DeferredShape),
}

impl SP1ProofShape {
    pub fn generate<'a>(
        core_shape_config: &'a CoreShapeConfig<BabyBear>,
        recursion_shape_config: &'a RecursionShapeConfig<BabyBear, CompressAir<BabyBear>>,
        reduce_batch_size: usize,
    ) -> impl Iterator<Item = Self> + 'a {
        core_shape_config
            .generate_all_allowed_shapes()
            .map(Self::Recursion)
            .chain(
                recursion_shape_config
                    .get_all_shape_combinations(1)
                    .map(|mut x| Self::Deferred(x.pop().unwrap())),
            )
            .chain(
                recursion_shape_config
                    .get_all_shape_combinations(reduce_batch_size)
                    .map(Self::Compress),
            )
    }
}

impl SP1CompressProgramShape {
    pub fn from_proof_shape(shape: SP1ProofShape, height: usize) -> Self {
        match shape {
            SP1ProofShape::Recursion(proof_shape) => Self::Recursion(proof_shape.into()),
            SP1ProofShape::Deferred(proof_shape) => Self::Deferred(proof_shape.into()),
            SP1ProofShape::Compress(proof_shapes) => Self::Compress(SP1CompressWithVkeyShape {
                compress_shape: proof_shapes.into(),
                merkle_tree_height: height,
            }),
        }
    }
}

impl<C: SP1ProverComponents> SP1Prover<C> {
    pub fn program_from_shape(
        &self,
        shape: SP1CompressProgramShape,
    ) -> Arc<RecursionProgram<BabyBear>> {
        match shape {
            SP1CompressProgramShape::Recursion(shape) => {
                let input = SP1RecursionWitnessValues::dummy(self.core_prover.machine(), &shape);
                self.recursion_program(&input)
            }
            SP1CompressProgramShape::Deferred(shape) => {
                let input = SP1DeferredWitnessValues::dummy(self.compress_prover.machine(), &shape);
                self.deferred_program(&input)
            }
            SP1CompressProgramShape::Compress(shape) => {
                let input =
                    SP1CompressWithVKeyWitnessValues::dummy(self.compress_prover.machine(), &shape);
                self.compress_program(&input)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_all_shapes() {
        let core_shape_config = CoreShapeConfig::default();
        let recursion_shape_config = RecursionShapeConfig::default();
        let reduce_batch_size = 2;
        let num_compress_shapes =
            SP1ProofShape::generate(&core_shape_config, &recursion_shape_config, reduce_batch_size)
                .count();
        println!("Number of compress shapes: {}", num_compress_shapes);
    }
}
