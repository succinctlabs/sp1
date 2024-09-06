use std::marker::PhantomData;

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
    allowed_log_heights: HashMap<String, Vec<usize>>,
    _marker: PhantomData<(F, A)>,
}

impl<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize, const COL_PADDING: usize>
    RecursionShapeConfig<F, RecursionAir<F, DEGREE, COL_PADDING>>
{
    pub fn fix_shape(&self, program: &mut RecursionProgram<F>) {
        if program.shape.is_some() {
            tracing::warn!("recursion shape already fixed");
            // TODO: Change this to not panic (i.e. return);
            panic!("cannot fix recursion shape twice");
        }

        let shape = RecursionAir::<F, DEGREE, COL_PADDING>::heights(program)
            .into_iter()
            .map(|(name, height)| {
                for &allowed_log_height in self.allowed_log_heights.get(&name).unwrap() {
                    let allowed_height = 1 << allowed_log_height;
                    if height <= allowed_height {
                        return (name, allowed_log_height);
                    }
                }
                panic!("air {} not allowed at height {}", name, height);
            })
            .collect();

        let shape = RecursionShape { inner: shape };
        program.shape = Some(shape);
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize, const COL_PADDING: usize>
    Default for RecursionShapeConfig<F, RecursionAir<F, DEGREE, COL_PADDING>>
{
    fn default() -> Self {
        let mem_const_heights = vec![16, 18, 19];
        let mem_var_heights = vec![18, 19, 20];
        let base_alu_heights = vec![20, 21, 22];
        let ext_alu_heights = vec![20, 21, 22];
        let poseidon2_wide_heights = vec![16, 18, 19];
        let exp_reverse_bits_len_heights = vec![16, 18, 19];
        let public_values_heights = vec![PUB_VALUES_LOG_HEIGHT];

        let allowed_log_heights = HashMap::from(
            [
                (
                    RecursionAir::<F, DEGREE, COL_PADDING>::MemoryConst(MemoryConstChip::default()),
                    mem_const_heights,
                ),
                (
                    RecursionAir::<F, DEGREE, COL_PADDING>::MemoryVar(MemoryVarChip::default()),
                    mem_var_heights,
                ),
                (RecursionAir::<F, DEGREE, COL_PADDING>::BaseAlu(BaseAluChip), base_alu_heights),
                (RecursionAir::<F, DEGREE, COL_PADDING>::ExtAlu(ExtAluChip), ext_alu_heights),
                (
                    RecursionAir::<F, DEGREE, COL_PADDING>::Poseidon2Wide(
                        Poseidon2WideChip::<DEGREE>,
                    ),
                    poseidon2_wide_heights,
                ),
                (
                    RecursionAir::<F, DEGREE, COL_PADDING>::ExpReverseBitsLen(
                        ExpReverseBitsLenChip::<DEGREE>,
                    ),
                    exp_reverse_bits_len_heights,
                ),
                (
                    RecursionAir::<F, DEGREE, COL_PADDING>::PublicValues(PublicValuesChip),
                    public_values_heights,
                ),
            ]
            .map(|(air, heights)| (air.name(), heights)),
        );

        Self { allowed_log_heights, _marker: PhantomData }
    }
}
