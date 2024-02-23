use std::time::Instant;

use crate::utils::poseidon2_instance::RC_16_30;
use crate::{
    runtime::{Program, Runtime},
    stark::{LocalProver, OpeningProof, ShardMainData},
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
        Challenge = Self::Challenge,
        Pcs = Self::Pcs,
        Challenger = Self::Challenger,
    >;
    fn challenger(&self) -> Self::Challenger;

    fn uni_stark_config(&self) -> &Self::UniConfig;
}

pub fn get_cycles(program: Program) -> u64 {
    let mut runtime = Runtime::new(program);
    runtime.run();
    runtime.state.global_clk as u64
}

pub fn prove(program: Program) -> crate::stark::Proof<BabyBearBlake3> {
    let runtime = tracing::info_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Runtime::new(program);
        runtime.run();
        runtime
    });
    let config = BabyBearBlake3::new();
    prove_core(config, runtime)
}

#[cfg(test)]
pub fn run_test(program: Program) -> Result<(), crate::stark::ProgramVerificationError> {
    #[cfg(not(feature = "perf"))]
    use crate::lookup::{debug_interactions_with_all_chips, InteractionKind};

    let runtime = tracing::info_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Runtime::new(program);
        runtime.run();
        runtime
    });
    let config = BabyBearBlake3::new();

    let machine = RiscvStark::new(config);
    let (pk, vk) = machine.setup(runtime.program.as_ref());
    let mut challenger = machine.config().challenger();

    let start = Instant::now();
    let proof = tracing::info_span!("runtime.prove(...)")
        .in_scope(|| machine.prove::<LocalProver<_>>(&pk, runtime.record, &mut challenger));

    #[cfg(not(feature = "perf"))]
    assert!(debug_interactions_with_all_chips(
        &machine.chips(),
        &runtime.record,
        InteractionKind::all_kinds(),
    ));
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

    let mut challenger = machine.config().challenger();
    machine.verify(&vk, &proof, &mut challenger)
}

pub fn prove_elf(elf: &[u8]) -> crate::stark::Proof<BabyBearBlake3> {
    let program = Program::from(elf);
    prove(program)
}

pub fn prove_core<SC: StarkGenericConfig + StarkUtils + Send + Sync + Serialize>(
    config: SC,
    runtime: Runtime,
) -> crate::stark::Proof<SC>
where
    SC::Challenger: Clone,
    OpeningProof<SC>: Send + Sync,
    <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::Commitment: Send + Sync,
    <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::ProverData: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    let mut challenger = config.challenger();

    let start = Instant::now();

    let machine = RiscvStark::new(config);
    let (pk, _) = machine.setup(runtime.program.as_ref());

    // Prove the program.
    let cycles = runtime.state.global_clk;
    let proof = tracing::info_span!("runtime.prove(...)")
        .in_scope(|| machine.prove::<LocalProver<_>>(&pk, runtime.record, &mut challenger));
    let time = start.elapsed().as_millis();
    let nb_bytes = bincode::serialize(&proof).unwrap().len();

    tracing::info!(
        "cycles={}, e2e={}, khz={:.2}, proofSize={}",
        cycles,
        time,
        (cycles as f64 / time as f64),
        Size::from_bytes(nb_bytes),
    );

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
        + for<'a> Air<p3_uni_stark::DebugConstraintBuilder<'a, SC::Val>>,
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
        + for<'a> Air<p3_uni_stark::DebugConstraintBuilder<'a, SC::Val>>,
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
    use serde::{Deserialize, Serialize};

    use crate::stark::StarkGenericConfig;

    use super::StarkUtils;

    pub type Val = BabyBear;

    pub type Challenge = BinomialExtensionField<Val, 4>;

    pub type Perm = Poseidon2<Val, DiffusionMatrixBabybear, 16, 5>;
    pub type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;

    pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;

    pub type ValMmcs = FieldMerkleTreeMmcs<
        <Val as Field>::Packing,
        <Val as Field>::Packing,
        MyHash,
        MyCompress,
        8,
    >;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

    pub type Dft = Radix2DitParallel;

    pub type Challenger = DuplexChallenger<Val, Perm, 16>;

    type Pcs =
        TwoAdicFriPcs<TwoAdicFriPcsConfig<Val, Challenge, Challenger, Dft, ValMmcs, ChallengeMmcs>>;

    #[derive(Deserialize)]
    #[serde(from = "std::marker::PhantomData<BabyBearPoseidon2>")]
    pub struct BabyBearPoseidon2 {
        perm: Perm,
        pcs: Pcs,
    }

    /// Implement serialization manually instead of using serde to avoid cloing the config.
    impl Serialize for BabyBearPoseidon2 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            std::marker::PhantomData::<BabyBearPoseidon2>.serialize(serializer)
        }
    }

    impl From<std::marker::PhantomData<BabyBearPoseidon2>> for BabyBearPoseidon2 {
        fn from(_: std::marker::PhantomData<BabyBearPoseidon2>) -> Self {
            Self::new()
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
        type Pcs = Pcs;
        type Challenger = Challenger;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }
    }

    impl p3_uni_stark::StarkGenericConfig for BabyBearPoseidon2 {
        type Val = Val;
        type Challenge = Challenge;
        type Pcs = Pcs;
        type Challenger = Challenger;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }
    }
}

pub(super) mod baby_bear_keccak {

    use p3_baby_bear::BabyBear;
    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriConfig, TwoAdicFriPcs, TwoAdicFriPcsConfig};
    use p3_keccak::Keccak256Hash;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
    use serde::{Deserialize, Serialize};

    use crate::stark::StarkGenericConfig;

    use super::StarkUtils;

    pub type Val = BabyBear;

    pub type Challenge = BinomialExtensionField<Val, 4>;

    type ByteHash = Keccak256Hash;
    type FieldHash = SerializingHasher32<ByteHash>;

    type MyCompress = CompressionFunctionFromHasher<u8, ByteHash, 2, 32>;

    pub type ValMmcs = FieldMerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

    pub type Dft = Radix2DitParallel;

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

    type Pcs =
        TwoAdicFriPcs<TwoAdicFriPcsConfig<Val, Challenge, Challenger, Dft, ValMmcs, ChallengeMmcs>>;

    #[derive(Deserialize)]
    #[serde(from = "std::marker::PhantomData<BabyBearKeccak>")]
    pub struct BabyBearKeccak {
        pcs: Pcs,
    }
    // Implement serialization manually instead of using serde(into) to avoid cloing the config
    impl Serialize for BabyBearKeccak {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            std::marker::PhantomData::<BabyBearKeccak>.serialize(serializer)
        }
    }

    impl From<std::marker::PhantomData<BabyBearKeccak>> for BabyBearKeccak {
        fn from(_: std::marker::PhantomData<BabyBearKeccak>) -> Self {
            Self::new()
        }
    }

    impl BabyBearKeccak {
        #[allow(dead_code)]
        pub fn new() -> Self {
            let byte_hash = ByteHash {};
            let field_hash = FieldHash::new(byte_hash);

            let compress = MyCompress::new(byte_hash);

            let val_mmcs = ValMmcs::new(field_hash, compress);

            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            let dft = Dft {};

            let fri_config = FriConfig {
                log_blowup: 1,
                num_queries: 100,
                proof_of_work_bits: 16,
                mmcs: challenge_mmcs,
            };
            let pcs = Pcs::new(fri_config, dft, val_mmcs);

            Self { pcs }
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
            Challenger::from_hasher(vec![], ByteHash {})
        }

        fn uni_stark_config(&self) -> &Self::UniConfig {
            self
        }
    }

    impl StarkGenericConfig for BabyBearKeccak {
        type Val = Val;
        type Challenge = Challenge;
        type Pcs = Pcs;
        type Challenger = Challenger;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }
    }

    impl p3_uni_stark::StarkGenericConfig for BabyBearKeccak {
        type Val = Val;
        type Challenge = Challenge;
        type Pcs = Pcs;
        type Challenger = Challenger;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }
    }
}

pub(super) mod baby_bear_blake3 {

    use p3_baby_bear::BabyBear;
    use p3_blake3::Blake3;
    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriConfig, TwoAdicFriPcs, TwoAdicFriPcsConfig};
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
    use serde::{Deserialize, Serialize};

    use crate::stark::StarkGenericConfig;

    use super::StarkUtils;

    pub type Val = BabyBear;

    pub type Challenge = BinomialExtensionField<Val, 4>;

    type ByteHash = Blake3;
    type FieldHash = SerializingHasher32<ByteHash>;

    type MyCompress = CompressionFunctionFromHasher<u8, ByteHash, 2, 32>;

    pub type ValMmcs = FieldMerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

    pub type Dft = Radix2DitParallel;

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

    type Pcs =
        TwoAdicFriPcs<TwoAdicFriPcsConfig<Val, Challenge, Challenger, Dft, ValMmcs, ChallengeMmcs>>;

    #[derive(Deserialize)]
    #[serde(from = "std::marker::PhantomData<BabyBearBlake3>")]
    pub struct BabyBearBlake3 {
        pcs: Pcs,
    }

    // Implement serialization manually instead of using serde(into) to avoid cloing the config
    impl Serialize for BabyBearBlake3 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            std::marker::PhantomData::<Self>.serialize(serializer)
        }
    }

    impl From<std::marker::PhantomData<BabyBearBlake3>> for BabyBearBlake3 {
        fn from(_: std::marker::PhantomData<BabyBearBlake3>) -> Self {
            Self::new()
        }
    }

    impl BabyBearBlake3 {
        pub fn new() -> Self {
            let byte_hash = ByteHash {};
            let field_hash = FieldHash::new(byte_hash);

            let compress = MyCompress::new(byte_hash);

            let val_mmcs = ValMmcs::new(field_hash, compress);

            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            let dft = Dft {};

            let fri_config = FriConfig {
                log_blowup: 1,
                num_queries: 100,
                proof_of_work_bits: 16,
                mmcs: challenge_mmcs,
            };
            let pcs = Pcs::new(fri_config, dft, val_mmcs);

            Self { pcs }
        }
    }

    impl StarkUtils for BabyBearBlake3 {
        type UniConfig = Self;

        fn challenger(&self) -> Self::Challenger {
            Challenger::from_hasher(vec![], ByteHash {})
        }

        fn uni_stark_config(&self) -> &Self::UniConfig {
            self
        }
    }

    impl StarkGenericConfig for BabyBearBlake3 {
        type Val = Val;
        type Challenge = Challenge;

        type Pcs = Pcs;
        type Challenger = Challenger;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }
    }

    impl p3_uni_stark::StarkGenericConfig for BabyBearBlake3 {
        type Val = Val;
        type Challenge = Challenge;

        type Pcs = Pcs;
        type Challenger = Challenger;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }
    }
}
