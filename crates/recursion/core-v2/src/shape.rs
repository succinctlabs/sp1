use hashbrown::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecursionShape {
    pub id: usize,
    pub shape: HashMap<String, usize>,
}

// let chips = [
//     RecursionAir::MemoryConst(MemoryConstChip {
//         fixed_log2_rows: Some(16),
//         _data: PhantomData,
//     }),
//     RecursionAir::MemoryVar(MemoryVarChip {
//         fixed_log2_rows: Some(18),
//         _data: PhantomData,
//     }),
//     RecursionAir::BaseAlu(BaseAluChip { fixed_log2_rows: Some(20) }),
//     RecursionAir::ExtAlu(ExtAluChip { fixed_log2_rows: Some(22) }),
//     RecursionAir::Poseidon2Wide(Poseidon2WideChip::<DEGREE> { fixed_log2_rows: Some(16) }),
//     RecursionAir::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE> {
//         fixed_log2_rows: Some(16),
//     }),
//     RecursionAir::PublicValues(PublicValuesChip::default()),
// ]
// .map(Chip::new)
// .into_iter()
// .collect::<Vec<_>>();
// StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
