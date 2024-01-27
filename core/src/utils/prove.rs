use std::time::Instant;

use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{extension::BinomialExtensionField, Field};
use p3_fri::{FriBasedPcs, FriConfigImpl, FriLdt};
use p3_keccak::Keccak256Hash;
use p3_ldt::QuotientMmcs;
use p3_mds::coset_mds::CosetMds;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
use p3_uni_stark::StarkConfigImpl;
use rand::thread_rng;

use crate::runtime::{Program, Runtime};

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
    type Val = BabyBear;
    type Domain = Val;
    type Challenge = BinomialExtensionField<Val, 4>;
    type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

    type MyMds = CosetMds<Val, 16>;
    let mds = MyMds::default();

    type Perm = Poseidon2<Val, MyMds, DiffusionMatrixBabybear, 16, 5>;
    let perm = Perm::new_from_rng(8, 22, mds, DiffusionMatrixBabybear, &mut thread_rng());

    type MyHash = SerializingHasher32<Keccak256Hash>;
    let hash = MyHash::new(Keccak256Hash {});

    type MyCompress = CompressionFunctionFromHasher<Val, MyHash, 2, 8>;
    let compress = MyCompress::new(hash);

    type ValMmcs = FieldMerkleTreeMmcs<Val, MyHash, MyCompress, 8>;
    let val_mmcs = ValMmcs::new(hash, compress);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    type Dft = Radix2DitParallel;
    let dft = Dft {};

    type Challenger = DuplexChallenger<Val, Perm, 16>;

    type Quotient = QuotientMmcs<Domain, Challenge, ValMmcs>;
    type MyFriConfig = FriConfigImpl<Val, Challenge, Quotient, ChallengeMmcs, Challenger>;
    let fri_config = MyFriConfig::new(1, 40, challenge_mmcs);
    let ldt = FriLdt { config: fri_config };

    type Pcs = FriBasedPcs<MyFriConfig, ValMmcs, Dft, Challenger>;
    type MyConfig = StarkConfigImpl<Val, Challenge, PackedChallenge, Pcs, Challenger>;

    let pcs = Pcs::new(dft, val_mmcs, ldt);
    let config = StarkConfigImpl::new(pcs);
    let mut challenger = Challenger::new(perm.clone());

    tracing::info!(
        "total_cycles: {}, segments: {}",
        runtime
            .segments
            .iter()
            .map(|s| s.cpu_events.len())
            .sum::<usize>(),
        runtime.segments.len()
    );

    let start = Instant::now();

    tracing::info_span!("runtime.prove(...)").in_scope(|| {
        runtime.prove::<_, _, MyConfig>(&config, &mut challenger);
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
