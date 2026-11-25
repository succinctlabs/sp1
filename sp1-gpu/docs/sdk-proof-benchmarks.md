# SDK and CUDA server proof benchmarks

24 November 2026. Benchmarked the working tree against branch commit `03adf8d0c35560902d23fba30e9140aac2eb7a0f` on one GeForce RTX 4090. Across the three workloads that completed on both builds, the requested modes cut median proving time by at least 26.4% and peak host RSS by at least 33.2%. The highest observed optimized peak across all five workloads and all four measured modes was 12.16 GiB.

## Completed baseline comparisons

Each build ran three fresh sessions per cell. Times are median seconds spent in the SDK proof calls. RSS is the largest simultaneous SDK-client-plus-server sample across all three sessions. A Groth16 or PLONK session proves the same input twice with one server.

| Guest | Core shards | Mode | Branch, s | Optimized, s | Time reduction | Branch, GiB | Optimized, GiB | RSS reduction |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fibonacci 1,000 | 2 | Compressed | 1.006 | 0.704 | 30.0% | 4.30 | 1.88 | 56.2% |
| Fibonacci 1,000 | 2 | 2× Groth16 | 17.922 | 12.918 | 27.9% | 13.69 | 6.78 | 50.4% |
| Fibonacci 1,000 | 2 | 2× PLONK | 29.511 | 20.811 | 29.5% | 12.21 | 6.79 | 44.4% |
| Fibonacci 1,000 | 2 | Core | 0.368 | 0.211 | 42.7% | 3.91 | 1.53 | 60.7% |
| Fibonacci 1,000,000 | 9 | Compressed | 4.761 | 3.436 | 27.8% | 5.67 | 3.78 | 33.2% |
| Fibonacci 1,000,000 | 9 | 2× Groth16 | 25.182 | 18.445 | 26.8% | 14.13 | 8.95 | 36.7% |
| Fibonacci 1,000,000 | 9 | 2× PLONK | 36.734 | 26.881 | 26.8% | 12.66 | 8.05 | 36.4% |
| Fibonacci 1,000,000 | 9 | Core | 2.256 | 1.900 | 15.8% | 5.23 | 3.93 | 24.9% |
| SHA-256 1 MiB | 8 | Compressed | 5.206 | 3.833 | 26.4% | 6.53 | 4.10 | 37.2% |
| SHA-256 1 MiB | 8 | 2× Groth16 | 26.883 | 19.593 | 27.1% | 14.73 | 8.46 | 42.5% |
| SHA-256 1 MiB | 8 | 2× PLONK | 37.783 | 27.634 | 26.9% | 13.18 | 8.30 | 37.0% |
| SHA-256 1 MiB | 8 | Core | 2.762 | 2.379 | 13.9% | 5.87 | 4.11 | 29.9% |

The 1,000-iteration Fibonacci control used the default height threshold of 4,194,304. Both builds used 262,144 for the million-iteration Fibonacci and 1 MiB SHA-256 comparisons. The raw core proofs supplied the shard counts.

## Larger workloads at the default shard limit

Fibonacci executed four million iterations. SHA-256 hashed two MiB of zero bytes. Each candidate entry summarizes three fresh sessions. Each branch entry records one attempted session.

| Guest | Core shards | Mode | Branch result | Optimized, s | Peak, GiB |
| --- | ---: | --- | --- | ---: | ---: |
| SHA-256, 2 MiB | 6 | Compressed | CUDA out of memory | 6.14 | 5.18 |
| SHA-256, 2 MiB | 6 | 2× Groth16 | CUDA out of memory | 23.79 | 9.77 |
| SHA-256, 2 MiB | 6 | 2× PLONK | CUDA out of memory | 32.37 | 10.41 |
| SHA-256, 2 MiB | 6 | Core | CUDA out of memory | 4.66 | 5.12 |
| Fibonacci, 4,000,000 | 8 | Compressed | CUDA out of memory | 9.11 | 7.53 |
| Fibonacci, 4,000,000 | 8 | 2× Groth16 | CUDA out of memory | 29.38 | 11.87 |
| Fibonacci, 4,000,000 | 8 | 2× PLONK | CUDA out of memory | 40.26 | 12.16 |
| Fibonacci, 4,000,000 | 8 | Core | CUDA out of memory | 6.16 | 7.10 |

## Prover changes

Groth16 streams large proving-key tables through bounded pinned host buffers. PLONK and Groth16 overlap key preparation with the STARK prover. Core shards reuse immutable program preprocessing and allocate host traces per AIR. The GPU prover estimates host and device workspace before admitting concurrent shards. When a large LogUp proof needs the memory occupied by an encoded trace, the prover releases it and re-encodes it for the FRI opening. Batched transforms, Merkle tree compression and direct FRI folding reduce GPU work.

Four repeated CPU/GPU transform comparisons passed under NVIDIA Compute Sanitizer. Twelve additional eight-shard SHA-256 compressed proofs verified with six core workers and 24 Rayon threads. These stress runs are separate from the performance trials.

## Measurement conditions

The same release SDK client launched the installed `~/.sp1/bin/sp1-gpu-server` for each trial. Each proof was independently verified by the SDK. A monotonic clock bracketed each `prove` call. SDK setup and independent verification fall outside those timers. The two-proof total includes both the first and repeat calls. The GPU server process and its proving-key cache started fresh in every session. Installed circuit files used the operating system’s normal page cache.

The sampler read resident pages for both PIDs from `/proc/<pid>/statm` and slept 4 ms between observations. It took the maximum of the simultaneous sum over setup, proving, verification and shutdown. Linux counts shared resident pages toward each process. GPU device memory is separate. Measurements cover the supplied guests, inputs and hardware.

The GPU had 17.86 to 19.60 GiB of device memory free at the start of the recorded sessions.

The highest sample occurred during Fibonacci, 4,000,000 in 2× PLONK mode. The client accounted for 48.7 MiB and the server accounted for 12.113 GiB.

Including transient helpers in the SDK process group, the highest observed optimized peak was 12.16 GiB. The trial data also records wall time from client launch through exit.

The runner rotated workload order and alternated which build ran first. A preflight required at least 75% idle CPU capacity and 70% free GPU memory. Sessions with more than eight logical CPUs of external load on average or more than sixteen in two consecutive one-second samples were excluded and repeated. The per-session CSV includes all accepted successes and the baseline GPU allocation failures for the default-size workloads. Individual first and repeat times, the RSS sample’s two components and host load are available in the [trial data](sdk-proof-benchmark-trials.csv).

| Item | Value |
| --- | --- |
| GPU | GeForce RTX 4090, 24,564 MiB |
| CPU | AMD Ryzen 9 5950X, 16 cores / 32 threads |
| Software | Linux 7.2.9, NVIDIA 615.71.09, CUDA 13.4.92, SP1 circuits v6.1.0 |
| Reference server SHA-256 | `02e9d9aee8ef282fd16a420afcd17b8cefc7ca0e8039e65f3c0d97a3c53ab06c` |
| Optimized server SHA-256 | `fb40f2a31cdc337eb724426c82bf103b9756e7f7c79ceb0f6c2363b01351c87a` |
| SDK runner SHA-256 | `0b4369451fcdbcec2f693e85a82f2b2d9388bacf8b2afa5f60704cbc9d502e64` |
| Source patch SHA-256 | `7e9a0f0b18624afd9c1724fce1d472be0e61ef334be4c76409bf0def2748b8f4` |

The accompanying evidence archive includes the reproducible source patch, sampler, SDK runner, build hashes, per-sample RSS and verification logs.

The follow-up benchmarks measured individual changes in both prover commits for each proof mode. [Per-change timings and peak RSS](sdk-proof-improvement-breakdown.md)
