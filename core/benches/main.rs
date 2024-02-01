use criterion::{black_box, criterion_group, criterion_main, Criterion};
use succinct_core::runtime::{Program, Runtime};
use succinct_core::utils::prove;

#[allow(unreachable_code)]
pub fn criterion_benchmark(c: &mut Criterion) {
    #[cfg(not(feature = "perf"))]
    unreachable!("--features=perf must be enabled to run this benchmark");

    let mut group = c.benchmark_group("prove");
    group.sample_size(10);
    let programs = ["fibonacci"];
    for p in programs {
        let elf_path = format!("../programs/{}/elf/riscv32im-succinct-zkvm-elf", p);
        let program = Program::from_elf(&elf_path);
        let cycles = {
            let mut runtime = Runtime::new(program.clone());
            runtime.run();
            runtime.global_clk
        };
        group.bench_function(
            format!("main:{}:{}", p.split('/').last().unwrap(), cycles),
            |b| b.iter(|| prove(black_box(program.clone()))),
        );
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
