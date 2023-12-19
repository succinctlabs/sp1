pub mod air;
pub mod trace;

#[derive(Debug, Clone, Copy)]
pub struct MemoryChip;

impl MemoryChip {
    pub fn new() -> Self {
        MemoryChip
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MemOp {
    Read = 0,
    Write = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryEvent {
    pub addr: u32,
    pub clk: u32,
    pub op: MemOp,
    pub value: u32,
}

// #[cfg(test)]
// mod tests {
//     use p3_air::{Air, AirBuilder};
//     use p3_challenger::DuplexChallenger;
//     use p3_dft::Radix2DitParallel;
//     use p3_field::Field;

//     use p3_baby_bear::BabyBear;
//     use p3_field::extension::BinomialExtensionField;
//     use p3_fri::{FriBasedPcs, FriConfigImpl, FriLdt};
//     use p3_keccak::Keccak256Hash;
//     use p3_ldt::QuotientMmcs;
//     use p3_matrix::dense::RowMajorMatrix;
//     use p3_mds::coset_mds::CosetMds;
//     use p3_merkle_tree::FieldMerkleTreeMmcs;
//     use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
//     use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
//     use p3_uni_stark::{prove, verify, StarkConfigImpl, SymbolicExpression, SymbolicVariable};
//     use rand::thread_rng;

//     use crate::lookup::InteractionBuilder;
//     use crate::memory::{MemOp, MemoryChip};
//     use crate::runtime::tests::get_simple_program;
//     use crate::runtime::Runtime;

//     use p3_commit::ExtensionMmcs;

//     use super::air::NUM_MEMORY_COLS;
//     use super::MemoryEvent;

//     #[test]
//     fn test_memory_generate_trace() {
//         let events = vec![
//             MemoryEvent {
//                 clk: 0,
//                 addr: 0,
//                 op: MemOp::Write,
//                 value: 0,
//             },
//             MemoryEvent {
//                 clk: 1,
//                 addr: 0,
//                 op: MemOp::Read,
//                 value: 0,
//             },
//         ];
//         let trace: RowMajorMatrix<BabyBear> = MemoryChip::generate_trace(&events);
//         println!("{:?}", trace.values)
//     }

//     #[test]
//     fn test_memory_prove_babybear() {
//         type Val = BabyBear;
//         type Domain = Val;
//         type Challenge = BinomialExtensionField<Val, 4>;
//         type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

//         type MyMds = CosetMds<Val, 16>;
//         let mds = MyMds::default();

//         type Perm = Poseidon2<Val, MyMds, DiffusionMatrixBabybear, 16, 5>;
//         let perm = Perm::new_from_rng(8, 22, mds, DiffusionMatrixBabybear, &mut thread_rng());

//         type MyHash = SerializingHasher32<Keccak256Hash>;
//         let hash = MyHash::new(Keccak256Hash {});

//         type MyCompress = CompressionFunctionFromHasher<Val, MyHash, 2, 8>;
//         let compress = MyCompress::new(hash);

//         type ValMmcs = FieldMerkleTreeMmcs<Val, MyHash, MyCompress, 8>;
//         let val_mmcs = ValMmcs::new(hash, compress);

//         type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
//         let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

//         type Dft = Radix2DitParallel;
//         let dft = Dft {};

//         type Challenger = DuplexChallenger<Val, Perm, 16>;

//         type Quotient = QuotientMmcs<Domain, Challenge, ValMmcs>;
//         type MyFriConfig = FriConfigImpl<Val, Challenge, Quotient, ChallengeMmcs, Challenger>;
//         let fri_config = MyFriConfig::new(40, challenge_mmcs);
//         let ldt = FriLdt { config: fri_config };

//         type Pcs = FriBasedPcs<MyFriConfig, ValMmcs, Dft, Challenger>;
//         type MyConfig = StarkConfigImpl<Val, Challenge, PackedChallenge, Pcs, Challenger>;

//         let pcs = Pcs::new(dft, val_mmcs, ldt);
//         let config = StarkConfigImpl::new(pcs);
//         let mut challenger = Challenger::new(perm.clone());

//         let code = get_simple_program();
//         let mut runtime = Runtime::new(code, 0);
//         runtime.run();
//         let events = runtime.memory_events;

//         let trace: RowMajorMatrix<BabyBear> = MemoryChip::generate_trace(&events);
//         let air = MemoryChip::new();
//         let proof = prove::<MyConfig, _>(&config, &air, &mut challenger, trace);

//         let mut challenger = Challenger::new(perm);
//         verify(&config, &air, &mut challenger, &proof).unwrap();
//     }

//     #[test]
//     fn test_memory_lookup_interactions() {
//         let air = MemoryChip::new();

//         let mut builder = InteractionBuilder::<BabyBear>::new(NUM_MEMORY_COLS);

//         air.eval(&mut builder);

//         let mut main = builder.main();
//         let (sends, receives) = builder.interactions();

//         for interaction in receives {
//             for value in interaction.values {
//                 let expr = value.apply::<SymbolicExpression<BabyBear>, SymbolicVariable<BabyBear>>(
//                     &[],
//                     &main.row_mut(0),
//                 );
//                 println!("{}", expr);
//             }
//         }

//         assert!(sends.is_empty());
//     }
// }
