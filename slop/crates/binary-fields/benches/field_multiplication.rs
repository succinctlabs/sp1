#![allow(clippy::disallowed_types)]

use core::ops::{Add, Div, Mul, Sub};

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use slop_algebra::{extension::BinomialExtensionField, AbstractExtensionField, AbstractField};
use slop_baby_bear::BabyBear;
use slop_binary_fields::GHash;
use slop_koala_bear::KoalaBear;

type BabyBearDegree4 = BinomialExtensionField<BabyBear, 4>;
type KoalaBearDegree4 = BinomialExtensionField<KoalaBear, 4>;

fn benchmark_field<T>(
    criterion: &mut Criterion,
    field_name: &str,
    operands_for_iteration: fn(u64) -> (T, T),
) where
    T: Copy + Add<T, Output = T> + Sub<T, Output = T> + Mul<T, Output = T> + Div<T, Output = T>,
{
    let mut group = criterion.benchmark_group(field_name);

    group.bench_function("addition", |bencher| {
        let mut iteration = 0;
        bencher.iter_batched(
            || next_operands(&mut iteration, operands_for_iteration),
            |(lhs, rhs)| black_box(lhs + rhs),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("subtraction", |bencher| {
        let mut iteration = 0;
        bencher.iter_batched(
            || next_operands(&mut iteration, operands_for_iteration),
            |(lhs, rhs)| black_box(lhs - rhs),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("multiplication", |bencher| {
        let mut iteration = 0;
        bencher.iter_batched(
            || next_operands(&mut iteration, operands_for_iteration),
            |(lhs, rhs)| black_box(lhs * rhs),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("division", |bencher| {
        let mut iteration = 0;
        bencher.iter_batched(
            || next_operands(&mut iteration, operands_for_iteration),
            |(lhs, rhs)| black_box(lhs / rhs),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn next_operands<T>(iteration: &mut u64, operands_for_iteration: fn(u64) -> (T, T)) -> (T, T) {
    *iteration = iteration.wrapping_add(1);
    operands_for_iteration(*iteration)
}

fn ghash_operands(iteration: u64) -> (GHash, GHash) {
    (
        GHash::new(mix(iteration), mix(iteration.wrapping_add(1))),
        GHash::new(mix(iteration.wrapping_add(2)) | 1, mix(iteration.wrapping_add(3))),
    )
}

fn baby_bear_operands(iteration: u64) -> (BabyBearDegree4, BabyBearDegree4) {
    let values: [BabyBear; 7] = core::array::from_fn(|offset| {
        BabyBear::from_wrapped_u32(mix(iteration.wrapping_add(offset as u64)) as u32)
    });
    (
        BabyBearDegree4::from_base_slice(&values[..4]),
        BabyBearDegree4::from_base_slice(&[values[4], values[5], values[6], BabyBear::one()]),
    )
}

fn koala_bear_operands(iteration: u64) -> (KoalaBearDegree4, KoalaBearDegree4) {
    let values: [KoalaBear; 7] = core::array::from_fn(|offset| {
        KoalaBear::from_wrapped_u32(mix(iteration.wrapping_add(offset as u64)) as u32)
    });
    (
        KoalaBearDegree4::from_base_slice(&values[..4]),
        KoalaBearDegree4::from_base_slice(&[values[4], values[5], values[6], KoalaBear::one()]),
    )
}

fn mix(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn benchmark_field_operations(criterion: &mut Criterion) {
    benchmark_field(criterion, "ghash_portable", ghash_operands);
    benchmark_field(criterion, "baby_bear_degree_4_scalar", baby_bear_operands);
    benchmark_field(criterion, "koala_bear_degree_4_scalar", koala_bear_operands);
}

criterion_group!(benches, benchmark_field_operations);
criterion_main!(benches);
