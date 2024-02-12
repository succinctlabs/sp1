use std::time::Instant;

use crate::utils::poseidon2_instance::RC_16_30;
use crate::{
    runtime::{Program, Runtime},
    stark::{LocalProver, MainData, OpeningProof},
    stark::{RiscvStark, StarkGenericConfig},
};
pub use baby_bear_blake3::BabyBearBlake3;
use p3_commit::Pcs;
use p3_field::PrimeField32;
use serde::de::DeserializeOwned;
use serde::Serialize;
use size::Size;

pub trait StarkUtils: StarkGenericConfig {
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
    runtime.state.global_clk as u64
}

pub fn prove(program: Program) -> crate::stark::Proof<BabyBearBlake3> {
    let mut runtime = tracing::info_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Runtime::new(program);
        runtime.run();
        runtime
    });
    let config = BabyBearBlake3::new();
    prove_core(config, &mut runtime)
}

pub fn prove_elf(elf: &[u8]) -> crate::stark::Proof<BabyBearBlake3> {
    let program = Program::from(elf);
    prove(program)
}

pub fn prove_core<SC: StarkGenericConfig + StarkUtils + Send + Sync + Serialize + Clone>(
    config: SC,
    runtime: &mut Runtime,
) -> crate::stark::Proof<SC>
where
    SC::Challenger: Clone,
    OpeningProof<SC>: Send + Sync,
    <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::Commitment: Send + Sync,
    <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::ProverData: Send + Sync,
    MainData<SC>: Serialize + DeserializeOwned,
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    let mut challenger = config.challenger();

    let start = Instant::now();

    let (machine, prover_data) = RiscvStark::init(config.clone());

    // Because proving modifies the shard, clone beforehand if we debug interactions.
    #[cfg(not(feature = "perf"))]
    let shard = runtime.record.clone();

    // Prove the program.
    let proof = tracing::info_span!("prove").in_scope(|| {
        machine.prove::<LocalProver<_>>(&prover_data, &mut runtime.record, &mut challenger)
    });
    let cycles = runtime.state.global_clk;
    let time = start.elapsed().as_millis();
    let nb_bytes = bincode::serialize(&proof).unwrap().len();

    tracing::info!(
        "cycles={}, e2e={}, khz={:.2}, proofSize={}",
        cycles,
        time,
        (cycles as f64 / time as f64),
        Size::from_bytes(nb_bytes),
    );

    #[cfg(not(feature = "perf"))]
    tracing::info_span!("debug interactions with all chips").in_scope(|| {
        debug_interactions_with_all_chips(
            &machine.chips(),
            &shard,
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

    proof
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

pub use baby_bear_keccak::BabyBearKeccak;
pub use baby_bear_poseidon2::BabyBearPoseidon2;
use p3_air::Air;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;

pub(super) mod baby_bear_poseidon2 {

    use crate::utils::prove::RC_16_30;
    use p3_baby_bear::BabyBear;
    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::{extension::BinomialExtensionField, Field};
    use p3_fri::{FriConfig, TwoAdicFriPcs, TwoAdicFriPcsConfig};
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use serde::Serialize;

    use crate::stark::StarkGenericConfig;

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

    impl Serialize for BabyBearPoseidon2 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_none()
        }
    }

    impl Clone for BabyBearPoseidon2 {
        fn clone(&self) -> Self {
            Self::new()
        }
    }

    impl BabyBearPoseidon2 {
        pub fn new() -> Self {
            let perm = Perm::new(8, 22, RC_16_30.to_vec(), DiffusionMatrixBabybear);

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

    impl StarkGenericConfig for BabyBearPoseidon2 {
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

    use crate::utils::prove::RC_16_30;
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
    use serde::Serialize;

    use crate::stark::StarkGenericConfig;

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

    impl Serialize for BabyBearKeccak {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_none()
        }
    }

    impl BabyBearKeccak {
        #[allow(dead_code)]
        pub fn new() -> Self {
            let perm = Perm::new(8, 22, RC_16_30.to_vec(), DiffusionMatrixBabybear);

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

    impl Clone for BabyBearKeccak {
        fn clone(&self) -> Self {
            Self::new()
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

    impl StarkGenericConfig for BabyBearKeccak {
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

    use crate::utils::prove::RC_16_30;
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
    use serde::Serialize;

    use crate::stark::StarkGenericConfig;

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

    impl Serialize for BabyBearBlake3 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_none()
        }
    }

    impl BabyBearBlake3 {
        pub fn new() -> Self {
            let perm = Perm::new(8, 22, RC_16_30.to_vec(), DiffusionMatrixBabybear);
            Self::from_perm(perm)
        }

        fn from_perm(perm: Perm) -> Self {
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

    impl Clone for BabyBearBlake3 {
        fn clone(&self) -> Self {
            Self::from_perm(self.perm.clone())
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

    impl StarkGenericConfig for BabyBearBlake3 {
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
