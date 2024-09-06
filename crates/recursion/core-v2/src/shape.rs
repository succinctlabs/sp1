use std::{hash::Hash, marker::PhantomData};

use hashbrown::HashMap;

use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use serde::{Deserialize, Serialize};
use sp1_stark::air::MachineAir;

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

impl<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize, const COL_PADDING: usize>
    RecursionShapeConfig<F, RecursionAir<F, DEGREE, COL_PADDING>>
{
    pub fn fix_shape(&self, program: &mut RecursionProgram<F>) {
        // if program.shape.is_some() {
        //     tracing::warn!("recursion shape already fixed");
        //     // TODO: Change this to not panic (i.e. return);
        //     panic!("cannot fix recursion shape twice");
        // }

        // let heights = RecursionAir::<F, DEGREE, COL_PADDING>::heights(program);
        // let shape = {
        //     for allowd in self.allowed_shapes.iter() {
        //         for (name, height) in heights.iter() {
        //             let bound;
        //         }
        //     }
        // };
        // // .into_iter()
        // // .map(|(name, height)| {
        // //     for &allowed_log_height in self.allowed_log_heights.get(&name).unwrap() {
        // //         let allowed_height = 1 << allowed_log_height;
        // //         if height <= allowed_height {
        // //             return (name, allowed_log_height);
        // //         }
        // //     }
        // //     panic!("air {} not allowed at height {}", name, height);
        // // })
        // // .collect();

        // let shape = RecursionShape { inner: shape };
        // program.shape = Some(shape);
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize, const COL_PADDING: usize>
    Default for RecursionShapeConfig<F, RecursionAir<F, DEGREE, COL_PADDING>>
{
    fn default() -> Self {
        Self { allowed_shapes: vec![], _marker: PhantomData }
    }
}
