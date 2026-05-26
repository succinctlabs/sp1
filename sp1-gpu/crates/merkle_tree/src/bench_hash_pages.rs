use std::time::Instant;

use rayon::prelude::*;
use slop_algebra::AbstractField;
use slop_symmetric::CryptographicHasher;
use sp1_gpu_cudart::{
    args, sys::merkle_tree::hash_pages_koala_bear_16_kernel, DeviceBuffer, TaskScope,
};
use sp1_primitives::{SP1Field, POSEIDON2_HASHER};

const DIGEST_WIDTH: usize = 8;
const WARMUP_ITERS: usize = 3;
const BENCH_ITERS: usize = 10;

fn generate_input(num_pages: usize, page_size: usize) -> Vec<SP1Field> {
    (0..num_pages * page_size)
        .map(|i| SP1Field::from_canonical_u32((i as u32).wrapping_mul(2654435761)))
        .collect()
}

fn cpu_hash_pages(input: &[SP1Field], num_pages: usize, page_size: usize) -> Vec<[SP1Field; 8]> {
    (0..num_pages)
        .map(|i| {
            let page = &input[i * page_size..(i + 1) * page_size];
            POSEIDON2_HASHER.hash_iter(page.iter().copied())
        })
        .collect()
}

fn cpu_hash_pages_parallel(
    input: &[SP1Field],
    num_pages: usize,
    page_size: usize,
) -> Vec<[SP1Field; 8]> {
    (0..num_pages)
        .into_par_iter()
        .map(|i| {
            let page = &input[i * page_size..(i + 1) * page_size];
            POSEIDON2_HASHER.hash_iter(page.iter().copied())
        })
        .collect()
}

fn gpu_hash_pages(
    scope: &TaskScope,
    input: &[SP1Field],
    num_pages: usize,
    page_size: usize,
) -> (Vec<SP1Field>, std::time::Duration) {
    let d_input = DeviceBuffer::from_host_slice(input, scope).unwrap();

    let total_digest_elems = num_pages * DIGEST_WIDTH;
    let mut d_digests =
        DeviceBuffer::<SP1Field>::with_capacity_in(total_digest_elems, scope.clone());
    unsafe {
        d_digests.set_len(total_digest_elems);
    }

    // Synchronize before timing
    scope.synchronize_blocking().unwrap();
    let start = Instant::now();

    let block_dim = 256usize;
    let grid_dim = num_pages.div_ceil(block_dim);
    let kernel = unsafe { hash_pages_koala_bear_16_kernel() };
    let args = args!(d_input.as_ptr(), d_digests.as_mut_ptr(), page_size, num_pages);
    unsafe {
        scope.launch_kernel(kernel, grid_dim, block_dim, &args, 0).unwrap();
    }

    scope.synchronize_blocking().unwrap();
    let elapsed = start.elapsed();

    let host_digests = d_digests.to_host().unwrap();
    (host_digests, elapsed)
}

#[test]
#[allow(clippy::print_stdout)]
fn bench_gpu_hash_pages() {
    let test_cases: Vec<(usize, usize)> = vec![
        (1024, 64),
        (1024, 128),
        (1024, 256),
        (1024, 512),
        (1024, 1024),
        (4096, 128),
        (4096, 256),
        (4096, 512),
        (4096, 1024),
        (8192, 128),
        (8192, 256),
        (8192, 512),
        (8192, 1024),
        (16384, 128),
        (16384, 256),
        (16384, 512),
        (16384, 1024),
        (32768, 128),
        (32768, 256),
        (32768, 512),
        (32768, 1024),
        (65536, 128),
        (65536, 256),
        (65536, 512),
        (65536, 1024),
    ];

    let num_cpus = rayon::current_num_threads();

    sp1_gpu_cudart::run_sync_in_place(|scope| {
        println!();
        println!("CPU threads: {num_cpus}");
        println!();
        println!(
            "{:<10} {:<10} {:<15} {:<15} {:<20} {:<15} {:<15} {:<10}",
            "N",
            "NUM_ADDRS",
            "GPU (ms)",
            "CPU 1T (ms)",
            "CPU Par (ms)",
            "GPU vs 1T",
            "GPU vs Par",
            "Correct"
        );
        println!("{}", "-".repeat(110));

        for &(num_pages, page_size) in &test_cases {
            let num_addrs = page_size;
            let page_size = page_size.div_ceil(3) * 8; // pack 3 addresses in 8 elements
            let input = generate_input(num_pages, page_size);

            // CPU single-threaded reference
            let cpu_start = Instant::now();
            let cpu_digests = cpu_hash_pages(&input, num_pages, page_size);
            let cpu_elapsed = cpu_start.elapsed();

            // CPU parallel (median of BENCH_ITERS)
            // Warmup
            for _ in 0..WARMUP_ITERS {
                let _ = cpu_hash_pages_parallel(&input, num_pages, page_size);
            }
            let mut cpu_par_times = Vec::with_capacity(BENCH_ITERS);
            for _ in 0..BENCH_ITERS {
                let start = Instant::now();
                let _ = cpu_hash_pages_parallel(&input, num_pages, page_size);
                cpu_par_times.push(start.elapsed());
            }
            cpu_par_times.sort();
            let cpu_par_median = cpu_par_times[BENCH_ITERS / 2];

            // GPU warmup
            for _ in 0..WARMUP_ITERS {
                let _ = gpu_hash_pages(&scope, &input, num_pages, page_size);
            }

            // GPU bench
            let mut gpu_times = Vec::with_capacity(BENCH_ITERS);
            let mut last_gpu_digests = Vec::new();
            for _ in 0..BENCH_ITERS {
                let (digests, elapsed) = gpu_hash_pages(&scope, &input, num_pages, page_size);
                gpu_times.push(elapsed);
                last_gpu_digests = digests;
            }

            // Use median GPU time
            gpu_times.sort();
            let gpu_median = gpu_times[BENCH_ITERS / 2];

            // Verify correctness
            let mut correct = true;
            for i in 0..num_pages {
                let gpu_digest = &last_gpu_digests[i * DIGEST_WIDTH..(i + 1) * DIGEST_WIDTH];
                if gpu_digest != cpu_digests[i].as_slice() {
                    correct = false;
                    eprintln!(
                        "MISMATCH at page {i}: GPU={:?}, CPU={:?}",
                        gpu_digest, &cpu_digests[i]
                    );
                    break;
                }
            }

            let gpu_ms = gpu_median.as_secs_f64() * 1000.0;
            let cpu_ms = cpu_elapsed.as_secs_f64() * 1000.0;
            let cpu_par_ms = cpu_par_median.as_secs_f64() * 1000.0;
            let speedup_1t = cpu_ms / gpu_ms;
            let speedup_par = cpu_par_ms / gpu_ms;

            println!(
                "{:<10} {:<10} {:<15.3} {:<15.3} {:<20.3} {:<15.1} {:<15.1} {:<10}",
                num_pages,
                num_addrs,
                gpu_ms,
                cpu_ms,
                cpu_par_ms,
                speedup_1t,
                speedup_par,
                if correct { "OK" } else { "FAIL" }
            );

            assert!(correct, "GPU/CPU mismatch for N={num_pages}, B={page_size}");
        }
        println!();
    })
    .unwrap();
}
