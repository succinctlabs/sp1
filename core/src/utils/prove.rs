use std::time::Instant;

use crate::{
    runtime::{Program, Runtime},
    stark::{LocalProver, StarkConfig},
};
pub use baby_bear_blake3::BabyBearBlake3;

pub trait StarkUtils: StarkConfig {
    type UniConfig: p3_uni_stark::StarkGenericConfig<
        Val = Self::Val,
        PackedVal = Self::PackedVal,
        Challenge = Self::Challenge,
        PackedChallenge = Self::PackedChallenge,
        Pcs = Self::Pcs,
        Challenger = Self::Challenger,
    >;
    fn challenger(&self) -> Self::Challenger;

    fn uni_stark_config(&self) -> &Self::UniConfig;
}

#[cfg(not(feature = "perf"))]
use crate::lookup::{debug_interactions_with_all_chips, InteractionKind};

pub fn get_cycles(program: Program) -> u64 {
    let mut runtime = Runtime::new(program);
    runtime.run();
    runtime.global_clk as u64
}

pub fn prove(program: Program) {
    let mut runtime = tracing::info_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Runtime::new(program);
        runtime.write_stdin_slice(&[1, 2]);
        runtime.run();
        runtime
    });
    prove_core(&mut runtime)
}

pub fn prove_elf(elf: &[u8]) {
    let program = Program::from(elf);
    prove(program)
}

pub fn prove_core(runtime: &mut Runtime) {
    let config = BabyBearK12::new(&mut rand::thread_rng());
    let mut challenger = config.challenger();

    let start = Instant::now();

    // Prove the program.
    let (segment_proofs, global_proof) = tracing::info_span!("runtime.prove(...)")
        .in_scope(|| runtime.prove::<_, _, _, LocalProver<_>>(&config, &mut challenger));

    #[cfg(not(feature = "perf"))]
    tracing::info_span!("debug interactions with all chips").in_scope(|| {
        println!("bruh");
        debug_interactions_with_all_chips(
            &mut runtime.segment,
            Some(&mut runtime.global_segment),
            vec![
                InteractionKind::Field,
                InteractionKind::Range,
                InteractionKind::Byte,
                InteractionKind::Alu,
                InteractionKind::Memory,
                InteractionKind::Program,
                InteractionKind::Instruction,
            ],
        );
    });

    let cycles = runtime.global_clk;
    let time = start.elapsed().as_millis();
    tracing::info!(
        "cycles={}, e2e={}, khz={:.2}",
        cycles,
        time,
        (cycles as f64 / time as f64),
    );

    // Verify the proof.
    let mut challenger = config.challenger();
    runtime
        .verify(&config, &mut challenger, &segment_proofs, &global_proof)
        .unwrap();
}

pub fn uni_stark_prove<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    trace: RowMajorMatrix<SC::Val>,
) -> Proof<SC::UniConfig>
where
    SC: StarkUtils,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::ProverConstraintFolder<'a, SC::UniConfig>>
        + for<'a> Air<p3_uni_stark::check_constraints::DebugConstraintBuilder<'a, SC::Val>>,
{
    p3_uni_stark::prove(config.uni_stark_config(), air, challenger, trace)
}

pub fn uni_stark_verify<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    proof: &Proof<SC::UniConfig>,
) -> Result<(), p3_uni_stark::VerificationError>
where
    SC: StarkUtils,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::VerifierConstraintFolder<'a, SC::Challenge>>
        + for<'a> Air<p3_uni_stark::check_constraints::DebugConstraintBuilder<'a, SC::Val>>,
{
    p3_uni_stark::verify(config.uni_stark_config(), air, challenger, proof)
}

pub use baby_bear_k12::BabyBearK12;
pub use baby_bear_keccak::BabyBearKeccak;
pub use baby_bear_poseidon2::BabyBearPoseidon2;
use p3_air::Air;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;

pub(super) mod baby_bear_poseidon2 {

    use p3_baby_bear::BabyBear;
    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::{extension::BinomialExtensionField, Field};
    use p3_fri::{FriConfig, TwoAdicFriPcs, TwoAdicFriPcsConfig};
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use rand::Rng;

    use crate::stark::StarkConfig;

    use super::StarkUtils;

    pub type Val = BabyBear;
    pub type Domain = Val;
    pub type Challenge = BinomialExtensionField<Val, 4>;
    pub type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

    pub type Perm = Poseidon2<Val, DiffusionMatrixBabybear, 16, 5>;
    pub type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;

    pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;

    pub type ValMmcs = FieldMerkleTreeMmcs<<Val as Field>::Packing, MyHash, MyCompress, 8>;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

    pub type Dft = Radix2DitParallel;

    pub type Challenger = DuplexChallenger<Val, Perm, 16>;

    type Pcs =
        TwoAdicFriPcs<TwoAdicFriPcsConfig<Val, Challenge, Challenger, Dft, ValMmcs, ChallengeMmcs>>;

    pub struct BabyBearPoseidon2 {
        perm: Perm,
        pcs: Pcs,
    }

    impl BabyBearPoseidon2 {
        pub fn new<R: Rng>(rng: &mut R) -> Self {
            let perm = Perm::new_from_rng(8, 22, DiffusionMatrixBabybear, rng);

            let hash = MyHash::new(perm.clone());

            let compress = MyCompress::new(perm.clone());

            let val_mmcs = ValMmcs::new(hash, compress);

            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            let dft = Dft {};

            let fri_config = FriConfig {
                log_blowup: 1,
                num_queries: 100,
                proof_of_work_bits: 16,
                mmcs: challenge_mmcs,
            };
            let pcs = Pcs::new(fri_config, dft, val_mmcs);

            Self { pcs, perm }
        }
    }

    impl StarkUtils for BabyBearPoseidon2 {
        type UniConfig = Self;

        fn challenger(&self) -> Self::Challenger {
            Challenger::new(self.perm.clone())
        }

        fn uni_stark_config(&self) -> &Self::UniConfig {
            self
        }
    }

    impl StarkConfig for BabyBearPoseidon2 {
        type Val = Val;
        type Challenge = Challenge;
        type PackedChallenge = PackedChallenge;
        type Pcs = Pcs;
        type Challenger = Challenger;
        type PackedVal = <Val as Field>::Packing;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }
    }

    impl p3_uni_stark::StarkGenericConfig for BabyBearPoseidon2 {
        type Val = Val;
        type Challenge = Challenge;
        type PackedChallenge = PackedChallenge;
        type Pcs = Pcs;
        type Challenger = Challenger;
        type PackedVal = <Val as Field>::Packing;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }
    }
}

pub(super) mod baby_bear_keccak {

    use p3_baby_bear::BabyBear;
    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::{extension::BinomialExtensionField, Field};
    use p3_fri::{FriConfig, TwoAdicFriPcs, TwoAdicFriPcsConfig};
    use p3_keccak::Keccak256Hash;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
    use p3_symmetric::{SerializingHasher32, TruncatedPermutation};
    use rand::Rng;

    use crate::stark::StarkConfig;

    use super::StarkUtils;

    pub type Val = BabyBear;
    pub type Domain = Val;
    pub type Challenge = BinomialExtensionField<Val, 4>;
    pub type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

    pub type Perm = Poseidon2<Val, DiffusionMatrixBabybear, 16, 7>;
    type MyHash = SerializingHasher32<Keccak256Hash>;

    pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;

    pub type ValMmcs = FieldMerkleTreeMmcs<Val, MyHash, MyCompress, 8>;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

    pub type Dft = Radix2DitParallel;

    pub type Challenger = DuplexChallenger<Val, Perm, 16>;

    type Pcs =
        TwoAdicFriPcs<TwoAdicFriPcsConfig<Val, Challenge, Challenger, Dft, ValMmcs, ChallengeMmcs>>;

    pub struct BabyBearKeccak {
        perm: Perm,
        pcs: Pcs,
    }

    impl BabyBearKeccak {
        #[allow(dead_code)]
        pub fn new<R: Rng>(rng: &mut R) -> Self {
            let perm = Perm::new_from_rng(8, 22, DiffusionMatrixBabybear, rng);

            let hash = MyHash::new(Keccak256Hash {});

            let compress = MyCompress::new(perm.clone());

            let val_mmcs = ValMmcs::new(hash, compress);

            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            let dft = Dft {};

            let fri_config = FriConfig {
                log_blowup: 1,
                num_queries: 100,
                proof_of_work_bits: 16,
                mmcs: challenge_mmcs,
            };
            let pcs = Pcs::new(fri_config, dft, val_mmcs);

            Self { pcs, perm }
        }
    }

    impl StarkUtils for BabyBearKeccak {
        type UniConfig = Self;

        fn challenger(&self) -> Self::Challenger {
            Challenger::new(self.perm.clone())
        }

        fn uni_stark_config(&self) -> &Self::UniConfig {
            self
        }
    }

    impl StarkConfig for BabyBearKeccak {
        type Val = Val;
        type Challenge = Challenge;
        type PackedChallenge = PackedChallenge;
        type Pcs = Pcs;
        type Challenger = Challenger;
        type PackedVal = <Val as Field>::Packing;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }
    }

    impl p3_uni_stark::StarkGenericConfig for BabyBearKeccak {
        type Val = Val;
        type Challenge = Challenge;
        type PackedChallenge = PackedChallenge;
        type Pcs = Pcs;
        type Challenger = Challenger;
        type PackedVal = <Val as Field>::Packing;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }
    }
}

pub(super) mod baby_bear_blake3 {

    use p3_baby_bear::BabyBear;
    use p3_blake3::Blake3;
    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::{extension::BinomialExtensionField, Field};
    use p3_fri::{FriConfig, TwoAdicFriPcs, TwoAdicFriPcsConfig};
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
    use p3_symmetric::{SerializingHasher32, TruncatedPermutation};
    use rand::Rng;

    use crate::stark::StarkConfig;

    use super::StarkUtils;

    pub type Val = BabyBear;
    pub type Domain = Val;
    pub type Challenge = BinomialExtensionField<Val, 4>;
    pub type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

    pub type Perm = Poseidon2<Val, DiffusionMatrixBabybear, 16, 7>;
    type MyHash = SerializingHasher32<Blake3>;

    pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;

    pub type ValMmcs = FieldMerkleTreeMmcs<Val, MyHash, MyCompress, 8>;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

    pub type Dft = Radix2DitParallel;

    pub type Challenger = DuplexChallenger<Val, Perm, 16>;

    type Pcs =
        TwoAdicFriPcs<TwoAdicFriPcsConfig<Val, Challenge, Challenger, Dft, ValMmcs, ChallengeMmcs>>;

    pub struct BabyBearBlake3 {
        perm: Perm,
        pcs: Pcs,
    }

    impl BabyBearBlake3 {
        pub fn new<R: Rng>(rng: &mut R) -> Self {
            let perm = Perm::new_from_rng(8, 22, DiffusionMatrixBabybear, rng);

            let hash = MyHash::new(Blake3 {});

            let compress = MyCompress::new(perm.clone());

            let val_mmcs = ValMmcs::new(hash, compress);

            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            let dft = Dft {};

            let fri_config = FriConfig {
                log_blowup: 1,
                num_queries: 100,
                proof_of_work_bits: 16,
                mmcs: challenge_mmcs,
            };
            let pcs = Pcs::new(fri_config, dft, val_mmcs);

            Self { pcs, perm }
        }
    }

    impl StarkUtils for BabyBearBlake3 {
        type UniConfig = Self;

        fn challenger(&self) -> Self::Challenger {
            Challenger::new(self.perm.clone())
        }

        fn uni_stark_config(&self) -> &Self::UniConfig {
            self
        }
    }

    impl StarkConfig for BabyBearBlake3 {
        type Val = Val;
        type Challenge = Challenge;
        type PackedChallenge = PackedChallenge;
        type Pcs = Pcs;
        type Challenger = Challenger;
        type PackedVal = <Val as Field>::Packing;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }
    }

    impl p3_uni_stark::StarkGenericConfig for BabyBearBlake3 {
        type Val = Val;
        type Challenge = Challenge;
        type PackedChallenge = PackedChallenge;
        type Pcs = Pcs;
        type Challenger = Challenger;
        type PackedVal = <Val as Field>::Packing;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }
    }
}

pub(super) mod baby_bear_k12 {

    use p3_baby_bear::BabyBear;
    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::{extension::BinomialExtensionField, Field};
    use p3_fri::{FriConfig, TwoAdicFriPcs, TwoAdicFriPcsConfig};
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
    use p3_symmetric::{SerializingHasher32, TruncatedPermutation};
    use rand::Rng;
    use succinct_k12::KangarooTwelve;

    use crate::stark::StarkConfig;

    use super::StarkUtils;

    pub type Val = BabyBear;
    pub type Domain = Val;
    pub type Challenge = BinomialExtensionField<Val, 4>;
    pub type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

    pub type Perm = Poseidon2<Val, DiffusionMatrixBabybear, 16, 7>;
    type MyHash = SerializingHasher32<KangarooTwelve>;

    pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;

    pub type ValMmcs = FieldMerkleTreeMmcs<Val, MyHash, MyCompress, 8>;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

    pub type Dft = Radix2DitParallel;

    pub type Challenger = DuplexChallenger<Val, Perm, 16>;

    type Pcs =
        TwoAdicFriPcs<TwoAdicFriPcsConfig<Val, Challenge, Challenger, Dft, ValMmcs, ChallengeMmcs>>;

    pub struct BabyBearK12 {
        perm: Perm,
        pcs: Pcs,
    }

    impl BabyBearK12 {
        pub fn new<R: Rng>(rng: &mut R) -> Self {
            let perm = Perm::new_from_rng(8, 22, DiffusionMatrixBabybear, rng);

            let hash = MyHash::new(KangarooTwelve {});

            let compress = MyCompress::new(perm.clone());

            let val_mmcs = ValMmcs::new(hash, compress);

            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            let dft = Dft {};

            let fri_config = FriConfig {
                log_blowup: 1,
                num_queries: 100,
                proof_of_work_bits: 16,
                mmcs: challenge_mmcs,
            };
            let pcs = Pcs::new(fri_config, dft, val_mmcs);

            Self { pcs, perm }
        }
    }

    impl StarkUtils for BabyBearK12 {
        type UniConfig = Self;

        fn challenger(&self) -> Self::Challenger {
            Challenger::new(self.perm.clone())
        }

        fn uni_stark_config(&self) -> &Self::UniConfig {
            self
        }
    }

    impl StarkConfig for BabyBearK12 {
        type Val = Val;
        type Challenge = Challenge;
        type PackedChallenge = PackedChallenge;
        type Pcs = Pcs;
        type Challenger = Challenger;
        type PackedVal = <Val as Field>::Packing;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }
    }

    impl p3_uni_stark::StarkGenericConfig for BabyBearK12 {
        type Val = Val;
        type Challenge = Challenge;
        type PackedChallenge = PackedChallenge;
        type Pcs = Pcs;
        type Challenger = Challenger;
        type PackedVal = <Val as Field>::Packing;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }
    }
}
