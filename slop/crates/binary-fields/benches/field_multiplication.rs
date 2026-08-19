#![allow(clippy::disallowed_types)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use slop_algebra::{extension::BinomialExtensionField, AbstractExtensionField, AbstractField};
use slop_baby_bear::BabyBear;
use slop_binary_fields::GHash;
use slop_koala_bear::KoalaBear;

type BabyBearDegree4 = BinomialExtensionField<BabyBear, 4>;
type KoalaBearDegree4 = BinomialExtensionField<KoalaBear, 4>;

fn benchmark_multiplication(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("field_multiplication");

    group.bench_function("ghash_portable", |bencher| {
        let lhs = GHash::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210);
        let rhs = GHash::new(0xdead_beef_cafe_babe, 0x1020_3040_5060_7080);
        bencher.iter(|| black_box(lhs) * black_box(rhs));
    });

    group.bench_function("baby_bear_degree_4_scalar", |bencher| {
        let lhs = BabyBearDegree4::from_base_slice(&[
            BabyBear::from_canonical_u32(1),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(3),
            BabyBear::from_canonical_u32(4),
        ]);
        let rhs = BabyBearDegree4::from_base_slice(&[
            BabyBear::from_canonical_u32(5),
            BabyBear::from_canonical_u32(6),
            BabyBear::from_canonical_u32(7),
            BabyBear::from_canonical_u32(8),
        ]);
        bencher.iter(|| black_box(lhs) * black_box(rhs));
    });

    group.bench_function("koala_bear_degree_4_scalar", |bencher| {
        let lhs = KoalaBearDegree4::from_base_slice(&[
            KoalaBear::from_canonical_u32(1),
            KoalaBear::from_canonical_u32(2),
            KoalaBear::from_canonical_u32(3),
            KoalaBear::from_canonical_u32(4),
        ]);
        let rhs = KoalaBearDegree4::from_base_slice(&[
            KoalaBear::from_canonical_u32(5),
            KoalaBear::from_canonical_u32(6),
            KoalaBear::from_canonical_u32(7),
            KoalaBear::from_canonical_u32(8),
        ]);
        bencher.iter(|| black_box(lhs) * black_box(rhs));
    });

    group.finish();
}

criterion_group!(benches, benchmark_multiplication);
criterion_main!(benches);
