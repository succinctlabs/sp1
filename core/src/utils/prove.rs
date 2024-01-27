use std::time::Instant;

use p3_uni_stark::StarkConfig;

use crate::runtime::{Program, Runtime};

pub trait StarkUtils: StarkConfig {
    fn challenger(&self) -> Self::Challenger;
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
        runtime.add_input_slice(&[1, 2]);
        runtime.run();
        runtime
    });
    prove_core(&mut runtime)
}

pub fn prove_core(runtime: &mut Runtime) {
    let config = BabyBearPoseidon2::new(&mut rand::thread_rng());
    let mut challenger = config.challenger();

    let start = Instant::now();

    tracing::info_span!("runtime.prove(...)").in_scope(|| {
        runtime.prove::<_, _, BabyBearPoseidon2>(&config, &mut challenger);
    });

    #[cfg(not(feature = "perf"))]
    tracing::info_span!("debug interactions with all chips").in_scope(|| {
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
}

pub use baby_bear_poseidon2::BabyBearPoseidon2;

pub(super) mod baby_bear_poseidon2 {

    use p3_baby_bear::BabyBear;
    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::{extension::BinomialExtensionField, Field};
    use p3_fri::{FriBasedPcs, FriConfigImpl, FriLdt};
    use p3_ldt::QuotientMmcs;
    use p3_mds::coset_mds::CosetMds;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use p3_uni_stark::StarkConfig;
    use rand::Rng;

    use super::StarkUtils;

    pub type Val = BabyBear;
    pub type Domain = Val;
    pub type Challenge = BinomialExtensionField<Val, 4>;
    pub type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

    pub type MyMds = CosetMds<Val, 16>;

    pub type Perm = Poseidon2<Val, MyMds, DiffusionMatrixBabybear, 16, 5>;
    pub type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;

    pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;

    pub type ValMmcs = FieldMerkleTreeMmcs<<Val as Field>::Packing, MyHash, MyCompress, 8>;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

    pub type Dft = Radix2DitParallel;

    pub type Challenger = DuplexChallenger<Val, Perm, 16>;

    pub type Quotient = QuotientMmcs<Domain, Challenge, ValMmcs>;
    pub type MyFriConfig = FriConfigImpl<Val, Challenge, Quotient, ChallengeMmcs, Challenger>;

    pub type Pcs = FriBasedPcs<MyFriConfig, ValMmcs, Dft, Challenger>;

    #[derive(Clone)]
    pub struct BabyBearPoseidon2 {
        perm: Perm,
        pcs: Pcs,
    }

    impl BabyBearPoseidon2 {
        pub fn new<R: Rng>(rng: &mut R) -> Self {
            let mds = MyMds::default();
            let perm = Perm::new_from_rng(8, 22, mds, DiffusionMatrixBabybear, rng);

            let hash = MyHash::new(perm.clone());

            let compress = MyCompress::new(perm.clone());

            let val_mmcs = ValMmcs::new(hash, compress);

            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            let dft = Dft {};

            let fri_config = MyFriConfig::new(1, 100, 16, challenge_mmcs);
            let ldt = FriLdt { config: fri_config };

            let pcs = Pcs::new(dft, val_mmcs, ldt);

            Self { pcs, perm }
        }
    }

    impl StarkUtils for BabyBearPoseidon2 {
        fn challenger(&self) -> Self::Challenger {
            Challenger::new(self.perm.clone())
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
}
