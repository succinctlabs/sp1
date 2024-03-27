use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sp1_core::runtime::{Program, Runtime};
use sp1_core::utils::{run_and_prove, BabyBearPoseidon2};

#[allow(unreachable_code)]
pub fn criterion_benchmark(c: &mut Criterion) {
    #[cfg(not(feature = "perf"))]
    unreachable!("--features=perf must be enabled to run this benchmark");

    let mut group = c.benchmark_group("prove");
    group.sample_size(10);
    let programs = ["fibonacci"];
    for p in programs {
        let elf_path = format!("../programs/demo/{}/elf/riscv32im-succinct-zkvm-elf", p);
        let program = Program::from_elf(&elf_path);
        let cycles = {
            let mut runtime = Runtime::new(program.clone());
            runtime.run();
            runtime.state.global_clk
        };
        group.bench_function(
            format!("main:{}:{}", p.split('/').last().unwrap(), cycles),
            |b| b.iter(|| run_and_prove(black_box(program.clone()), &[], BabyBearPoseidon2::new())),
        );
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
