use criterion::{criterion_group, criterion_main, Criterion};
use curta_core::runtime::Program;

use curta_core::runtime::Runtime;
use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::FriBasedPcs;
use p3_fri::FriConfigImpl;
use p3_fri::FriLdt;
use p3_keccak::Keccak256Hash;
use p3_ldt::QuotientMmcs;
use p3_mds::coset_mds::CosetMds;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::DiffusionMatrixBabybear;
use p3_poseidon2::Poseidon2;
use p3_symmetric::CompressionFunctionFromHasher;
use p3_symmetric::SerializingHasher32;
use p3_uni_stark::StarkConfigImpl;
use rand::thread_rng;

pub fn prove(program: Program) {
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
    let fri_config = MyFriConfig::new(40, challenge_mmcs);
    let ldt = FriLdt { config: fri_config };

    type Pcs = FriBasedPcs<MyFriConfig, ValMmcs, Dft, Challenger>;
    type MyConfig = StarkConfigImpl<Val, Challenge, PackedChallenge, Pcs, Challenger>;

    let pcs = Pcs::new(dft, val_mmcs, ldt);
    let config = StarkConfigImpl::new(pcs);
    let mut challenger = Challenger::new(perm.clone());

    let mut runtime = Runtime::new(program);
    runtime.write_witness(&[1, 2]);
    runtime.run();
    runtime.prove::<_, _, MyConfig>(&config, &mut challenger);
}

pub fn criterion_benchmark(c: &mut Criterion) {
    for program_name in &["fibonacci", "fib_malloc"] {
        let program = Program::from_elf(format!("../programs/{}.s", program_name).as_str());
        let mut group = c.benchmark_group(program_name.to_string());

        let mut runtime = Runtime::new(program.clone());
        runtime.write_witness(&[1, 2]);
        runtime.run();

        let cycles = runtime.segment.cpu_events.len();
        println!("{} cycles", cycles);

        group.throughput(criterion::Throughput::Elements(cycles as u64));
        group.sample_size(10);
        group.sampling_mode(criterion::SamplingMode::Flat);
        group.bench_function("prove", |b| b.iter(|| prove(program.clone())));
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
