use criterion::{black_box, criterion_group, criterion_main, Criterion};
use succinct_core::{
    runtime::{Program, Runtime},
    utils::prove,
};

pub fn criterion_benchmark(c: &mut Criterion) {
    #[cfg(not(feature = "perf"))]
    unreachable!("--features=perf must be enabled to run this benchmark");

    let mut group = c.benchmark_group("prove");
    group.sample_size(10);
    let programs = ["../programs/fibonacci"];
    for p in programs {
        let program = Program::from_elf(p);
        let cycles = {
            let mut runtime = Runtime::new(program.clone());
            runtime.run();
            runtime.global_clk
        };
        group.bench_function(
            format!("{}: cycles={}", p.split('/').last().unwrap(), cycles),
            |b| b.iter(|| prove(black_box(program.clone()))),
        );
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
