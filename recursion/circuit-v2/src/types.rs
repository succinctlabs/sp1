use hashbrown::HashMap;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_matrix::Dimensions;
use sp1_recursion_compiler::ir::Felt;

use crate::CircuitConfig;

/// Reference: [sp1_core::stark::StarkVerifyingKey]
#[derive(Clone)]
pub struct VerifyingKeyVariable<C: CircuitConfig> {
    pub commitment: C::Digest,
    pub pc_start: Felt<C::F>,
    pub chip_information: Vec<(String, TwoAdicMultiplicativeCoset<C::F>, Dimensions)>,
    pub chip_ordering: HashMap<String, usize>,
}
