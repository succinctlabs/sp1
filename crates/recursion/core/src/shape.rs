use std::marker::PhantomData;

use hashbrown::HashMap;

use itertools::Itertools;
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use serde::{Deserialize, Serialize};
use sp1_stark::{air::MachineAir, ProofShape};

use crate::{
    chips::{
        alu_base::BaseAluChip,
        alu_ext::ExtAluChip,
        exp_reverse_bits::ExpReverseBitsLenChip,
        mem::{MemoryConstChip, MemoryVarChip},
        poseidon2_wide::Poseidon2WideChip,
        public_values::{PublicValuesChip, PUB_VALUES_LOG_HEIGHT},
    },
    machine::RecursionAir,
    RecursionProgram, D,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecursionShape {
    pub(crate) inner: HashMap<String, usize>,
}

pub struct RecursionShapeConfig<F, A> {
    allowed_shapes: Vec<HashMap<String, usize>>,
    _marker: PhantomData<(F, A)>,
}

impl<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize>
    RecursionShapeConfig<F, RecursionAir<F, DEGREE>>
{
    pub fn fix_shape(&self, program: &mut RecursionProgram<F>) {
        let heights = RecursionAir::<F, DEGREE>::heights(program);
        // Get the allowed shape with a minimal hamming distance from the current shape.
        let mut min_distance = usize::MAX;
        let mut closest_shape = None;
        for shape in self.allowed_shapes.iter() {
            let mut distance = 0;
            let mut is_valid = true;
            for (name, height) in heights.iter() {
                let next_power_of_two = height.next_power_of_two();
                let allowed_log_height = shape.get(name).unwrap();
                let allowed_height = 1 << allowed_log_height;
                if next_power_of_two != allowed_height {
                    distance += 1;
                }
                if next_power_of_two > allowed_height {
                    is_valid = false;
                }
            }
            if is_valid && distance < min_distance {
                min_distance = distance;
                closest_shape = Some(shape.clone());
            }
        }

        if let Some(shape) = closest_shape {
            let shape = RecursionShape { inner: shape };
            program.shape = Some(shape);
        } else {
            panic!("no shape found for heights: {:?}", heights);
        }
    }

    pub fn get_all_shape_combinations(
        &self,
        batch_size: usize,
    ) -> impl Iterator<Item = Vec<ProofShape>> + '_ {
        (0..batch_size)
            .map(|_| {
                self.allowed_shapes
                    .iter()
                    .cloned()
                    .map(|map| map.into_iter().collect::<ProofShape>())
            })
            .multi_cartesian_product()
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize> Default
    for RecursionShapeConfig<F, RecursionAir<F, DEGREE>>
{
    fn default() -> Self {
        // Get the names of all the recursion airs to make the shape specification more readable.
        let mem_const = RecursionAir::<F, DEGREE>::MemoryConst(MemoryConstChip::default()).name();
        let mem_var = RecursionAir::<F, DEGREE>::MemoryVar(MemoryVarChip::default()).name();
        let base_alu = RecursionAir::<F, DEGREE>::BaseAlu(BaseAluChip).name();
        let ext_alu = RecursionAir::<F, DEGREE>::ExtAlu(ExtAluChip).name();
        let poseidon2_wide =
            RecursionAir::<F, DEGREE>::Poseidon2Wide(Poseidon2WideChip::<DEGREE>).name();
        let exp_reverse_bits_len =
            RecursionAir::<F, DEGREE>::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE>).name();
        let public_values = RecursionAir::<F, DEGREE>::PublicValues(PublicValuesChip).name();

        // Specify allowed shapes.
        let allowed_shapes = [
            [
                (base_alu.clone(), 20),
                (mem_var.clone(), 18),
                (ext_alu.clone(), 18),
                (exp_reverse_bits_len.clone(), 17),
                (mem_const.clone(), 17),
                (poseidon2_wide.clone(), 16),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (base_alu.clone(), 20),
                (mem_var.clone(), 18),
                (ext_alu.clone(), 18),
                (exp_reverse_bits_len.clone(), 17),
                (mem_const.clone(), 16),
                (poseidon2_wide.clone(), 16),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (ext_alu.clone(), 20),
                (base_alu.clone(), 19),
                (mem_var.clone(), 19),
                (poseidon2_wide.clone(), 17),
                (mem_const.clone(), 16),
                (exp_reverse_bits_len.clone(), 16),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (base_alu.clone(), 19),
                (mem_var.clone(), 18),
                (ext_alu.clone(), 18),
                (exp_reverse_bits_len.clone(), 17),
                (mem_const.clone(), 16),
                (poseidon2_wide.clone(), 16),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (base_alu.clone(), 19),
                (mem_var.clone(), 18),
                (ext_alu.clone(), 18),
                (exp_reverse_bits_len.clone(), 16),
                (mem_const.clone(), 16),
                (poseidon2_wide.clone(), 16),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (base_alu.clone(), 20),
                (mem_var.clone(), 19),
                (ext_alu.clone(), 19),
                (exp_reverse_bits_len.clone(), 17),
                (mem_const.clone(), 17),
                (poseidon2_wide.clone(), 17),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (base_alu.clone(), 21),
                (mem_var.clone(), 19),
                (ext_alu.clone(), 19),
                (exp_reverse_bits_len.clone(), 18),
                (mem_const.clone(), 18),
                (poseidon2_wide.clone(), 17),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (base_alu.clone(), 21),
                (mem_var.clone(), 19),
                (ext_alu.clone(), 19),
                (exp_reverse_bits_len.clone(), 18),
                (mem_const.clone(), 17),
                (poseidon2_wide.clone(), 17),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (ext_alu.clone(), 21),
                (base_alu.clone(), 20),
                (mem_var.clone(), 20),
                (poseidon2_wide.clone(), 18),
                (mem_const.clone(), 17),
                (exp_reverse_bits_len.clone(), 17),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (base_alu.clone(), 20),
                (mem_var.clone(), 19),
                (ext_alu.clone(), 19),
                (exp_reverse_bits_len.clone(), 18),
                (mem_const.clone(), 17),
                (poseidon2_wide.clone(), 17),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (base_alu.clone(), 20),
                (mem_var.clone(), 19),
                (ext_alu.clone(), 19),
                (exp_reverse_bits_len.clone(), 17),
                (mem_const.clone(), 17),
                (poseidon2_wide.clone(), 17),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (base_alu.clone(), 21),
                (mem_var.clone(), 20),
                (ext_alu.clone(), 20),
                (exp_reverse_bits_len.clone(), 18),
                (mem_const.clone(), 18),
                (poseidon2_wide.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
        ]
        .map(HashMap::from)
        .to_vec();
        Self { allowed_shapes, _marker: PhantomData }
    }
}
