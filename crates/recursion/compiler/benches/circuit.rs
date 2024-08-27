use std::time::Duration;

use criterion::*;
use p3_symmetric::Permutation;
use rand::{rngs::StdRng, Rng, SeedableRng};

use sp1_recursion_compiler::{
    asm::{AsmBuilder, AsmConfig},
    circuit::*,
    ir::{DslIr, TracedVec},
    prelude::Felt,
};
use sp1_recursion_core_v2::chips::poseidon2_wide::WIDTH;
use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, inner_perm, StarkGenericConfig};

type SC = BabyBearPoseidon2;
type F = <SC as StarkGenericConfig>::Val;
type EF = <SC as StarkGenericConfig>::Challenge;
type C = AsmConfig<F, EF>;

fn poseidon_program() -> TracedVec<DslIr<C>> {
    let mut builder = AsmBuilder::<F, EF>::default();
    let mut rng = StdRng::seed_from_u64(0xCAFEDA7E)
        .sample_iter::<[F; WIDTH], _>(rand::distributions::Standard);
    for _ in 0..100 {
        let input_1: [F; WIDTH] = rng.next().unwrap();
        let output_1 = inner_perm().permute(input_1);

        let input_1_felts = input_1.map(|x| builder.eval(x));
        let output_1_felts = builder.poseidon2_permute_v2(input_1_felts);
        let expected: [Felt<_>; WIDTH] = output_1.map(|x| builder.eval(x));
        for (lhs, rhs) in output_1_felts.into_iter().zip(expected) {
            builder.assert_felt_eq(lhs, rhs);
        }
    }
    builder.into_operations()
}

#[allow(dead_code)]
fn compile_one(c: &mut Criterion) {
    let input = {
        let mut ops = poseidon_program().vec;
        ops.truncate(100);
        ops
    };

    c.bench_with_input(
        BenchmarkId::new("compile_one", format!("{} instructions", input.len())),
        &input,
        |b, operations| {
            let mut compiler = AsmCompiler::<AsmConfig<F, EF>>::default();
            b.iter(|| {
                for instr in operations.iter().cloned() {
                    compiler.compile_one(std::hint::black_box(instr), drop);
                }
                compiler.next_addr = Default::default();
                compiler.virtual_to_physical.clear();
                compiler.consts.clear();
                compiler.addr_to_mult.clear();
            })
        },
    );
}

fn compile(c: &mut Criterion) {
    let input = poseidon_program();

    c.bench_with_input(
        BenchmarkId::new("compile", format!("{} instructions", input.vec.len())),
        &input,
        |b, operations| {
            let mut compiler = AsmCompiler::<AsmConfig<F, EF>>::default();
            b.iter(|| {
                compiler.compile(operations.clone());
            })
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(60));
    targets = compile
}
criterion_main!(benches);
