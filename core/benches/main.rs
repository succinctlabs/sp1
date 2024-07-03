use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sp1_core::io::SP1Stdin;
use sp1_core::runtime::{Program, Runtime};
use sp1_core::stark::DefaultProver;
use sp1_core::utils::{prove, BabyBearPoseidon2, SP1CoreOpts};

#[allow(unreachable_code)]
pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("prove");
    group.sample_size(10);
    let programs = ["fibonacci"];
    for p in programs {
        let elf_path = format!("../programs/demo/{}/elf/riscv32im-succinct-zkvm-elf", p);
        let program = Program::from_elf(&elf_path);
        let cycles = {
            let mut runtime = Runtime::new(program.clone(), SP1CoreOpts::default());
            runtime.run().unwrap();
            runtime.state.global_clk
        };
        group.bench_function(
            format!("main:{}:{}", p.split('/').last().unwrap(), cycles),
            |b| {
                b.iter(|| {
                    prove::<_, DefaultProver<_, _>>(
                        black_box(program.clone()),
                        &SP1Stdin::new(),
                        BabyBearPoseidon2::new(),
                        SP1CoreOpts::default(),
                    )
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
