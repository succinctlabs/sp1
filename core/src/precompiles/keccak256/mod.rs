mod execute;

// #[derive(Debug, Clone, Copy)]
// pub struct ShaCompressEvent {
//     pub clk: u32,
//     pub w_and_h_ptr: u32,
//     pub w: [u32; 64],
//     pub h: [u32; 8],
//     pub h_read_records: [Option<MemoryRecord>; 8],
//     pub w_i_read_records: [Option<MemoryRecord>; 64],
//     pub h_write_records: [Option<MemoryRecord>; 8],
// }

pub struct KeccakPermuteChip;

impl KeccakPermuteChip {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod compress_tests {
    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DitParallel;
    use p3_field::Field;

    use p3_baby_bear::BabyBear;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriBasedPcs, FriConfigImpl, FriLdt};
    use p3_keccak::Keccak256Hash;
    use p3_ldt::QuotientMmcs;
    use p3_mds::coset_mds::CosetMds;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
    use p3_uni_stark::StarkConfigImpl;
    use rand::thread_rng;

    use crate::runtime::{Instruction, Opcode, Program, Runtime};
    use p3_commit::ExtensionMmcs;

    #[test]
    pub fn keccak_permute_program() {
        let digest_ptr = 100;
        let mut instructions = vec![Instruction::new(Opcode::ADD, 29, 0, 5, false, true)];
        for i in 0..(25 * 8) {
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 30, 0, digest_ptr + i * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }
        instructions.extend(vec![
            Instruction::new(Opcode::ADD, 5, 0, 104, false, true),
            Instruction::new(Opcode::ADD, 10, 0, digest_ptr, false, true),
            Instruction::new(Opcode::ECALL, 10, 5, 0, false, true),
        ]);
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program);
        runtime.write_witness(&[999]);
        runtime.run()
    }

    // #[test]
    // fn prove_babybear() {
    //     type Val = BabyBear;
    //     type Domain = Val;
    //     type Challenge = BinomialExtensionField<Val, 4>;
    //     type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

    //     type MyMds = CosetMds<Val, 16>;
    //     let mds = MyMds::default();

    //     type Perm = Poseidon2<Val, MyMds, DiffusionMatrixBabybear, 16, 5>;
    //     let perm = Perm::new_from_rng(8, 22, mds, DiffusionMatrixBabybear, &mut thread_rng());

    //     type MyHash = SerializingHasher32<Keccak256Hash>;
    //     let hash = MyHash::new(Keccak256Hash {});

    //     type MyCompress = CompressionFunctionFromHasher<Val, MyHash, 2, 8>;
    //     let compress = MyCompress::new(hash);

    //     type ValMmcs = FieldMerkleTreeMmcs<Val, MyHash, MyCompress, 8>;
    //     let val_mmcs = ValMmcs::new(hash, compress);

    //     type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    //     let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    //     type Dft = Radix2DitParallel;
    //     let dft = Dft {};

    //     type Challenger = DuplexChallenger<Val, Perm, 16>;

    //     type Quotient = QuotientMmcs<Domain, Challenge, ValMmcs>;
    //     type MyFriConfig = FriConfigImpl<Val, Challenge, Quotient, ChallengeMmcs, Challenger>;
    //     let fri_config = MyFriConfig::new(40, challenge_mmcs);
    //     let ldt = FriLdt { config: fri_config };

    //     type Pcs = FriBasedPcs<MyFriConfig, ValMmcs, Dft, Challenger>;
    //     type MyConfig = StarkConfigImpl<Val, Challenge, PackedChallenge, Pcs, Challenger>;

    //     let pcs = Pcs::new(dft, val_mmcs, ldt);
    //     let config = StarkConfigImpl::new(pcs);
    //     let mut challenger = Challenger::new(perm.clone());

    //     let program = sha_compress_program();
    //     let mut runtime = Runtime::new(program);
    //     runtime.write_witness(&[999]);
    //     runtime.run();

    //     runtime.prove::<_, _, MyConfig>(&config, &mut challenger);
    // }
}
