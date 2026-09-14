//! Manual syscall-heavy benchmark using a compiled test-artifacts guest.
//! Run with --release --features profiling and reuse the same ELF for before/after comparisons.

use std::{sync::Arc, time::Instant};

use sp1_curves::{
    k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar},
    weierstrass::secp256k1::Secp256k1,
    AffinePoint, BigUint,
};
use test_artifacts::SECP256K1_BENCH_ELF;

use super::{arch::x86_64::MinimalExecutor as NativeExecutor, MinimalExecutor as PortableExecutor};
use crate::{Program, SupervisorMode};

#[test]
#[ignore = "manual release-mode native/portable secp256k1 benchmark"]
fn benchmark_secp256k1_executors() {
    assert!(!cfg!(debug_assertions), "run with --release --features profiling");
    assert!(std::env::var_os("TRACE_FILE").is_none(), "unset TRACE_FILE when benchmarking");
    const ITERATIONS: u32 = 16_384;

    let label = std::env::var("SECP256K1_BENCH_LABEL").unwrap_or_else(|_| "current".into());
    let program = Arc::new(Program::from(&SECP256K1_BENCH_ELF).unwrap());
    let words = |point: ProjectivePoint| -> [u64; 8] {
        let encoded = point.to_affine().to_encoded_point(false);
        AffinePoint::<Secp256k1>::new(
            BigUint::from_bytes_be(encoded.x().unwrap()),
            BigUint::from_bytes_be(encoded.y().unwrap()),
        )
        .to_words_le()
        .try_into()
        .unwrap()
    };
    let generator = words(ProjectivePoint::GENERATOR);
    // Start at 2G so even the first add uses distinct points.
    let initial = words(ProjectivePoint::GENERATOR.double());

    for name in ["add", "double", "mixed"] {
        let input = bincode::serialize(&(name, ITERATIONS, initial, generator)).unwrap();
        // Independently track P = scalar * G, then use k256 to compute the expected point.
        let mut scalar = Scalar::from(2u64);
        for _ in 0..ITERATIONS {
            scalar = match name {
                "add" => scalar + Scalar::ONE,
                "double" => scalar + scalar,
                "mixed" => scalar * Scalar::from(4u64) + Scalar::ONE,
                _ => unreachable!(),
            };
        }
        let expected =
            bincode::serialize(&(words(ProjectivePoint::GENERATOR * scalar), generator)).unwrap();
        let syscalls = u64::from(ITERATIONS) * if name == "mixed" { 3 } else { 1 };
        // The compiler determines the instruction count; require parity across runs/backends.
        let mut expected_cycles = None;

        macro_rules! measure {
            ($backend:ident) => {{
                let mut samples = Vec::new();
                for trial in 0..8 {
                    let mut executor = $backend::<SupervisorMode>::new(program.clone(), false, None);
                    executor.with_input(&input);
                    let start = Instant::now();
                    while executor.execute_chunk().is_some() {}
                    let elapsed = start.elapsed().as_secs_f64();
                    assert_eq!(executor.exit_code(), 0);
                    assert_eq!(executor.public_values_stream(), &expected);
                    let cycles = executor.global_clk();
                    assert!(cycles > 0);
                    assert_eq!(cycles, *expected_cycles.get_or_insert(cycles));
                    if trial != 0 {
                        samples.push(elapsed);
                    }
                }
                samples.sort_by(f64::total_cmp);
                eprintln!(
                    "{} {name} [{label}, bigint-rug={}]: {:.3} ms, {syscalls} EC syscalls, {} cycles (median of 7; range {:.3}..{:.3} ms)",
                    stringify!($backend), cfg!(feature = "bigint-rug"), samples[3] * 1000.,
                    expected_cycles.unwrap(), samples[0] * 1000., samples[6] * 1000.,
                );
            }};
        }
        measure!(NativeExecutor);
        measure!(PortableExecutor);
    }
}
