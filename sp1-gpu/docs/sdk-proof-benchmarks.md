# SDK and CUDA server proof benchmarks

On 24 November 2026, compressed proofs and pairs of Groth16 or PLONK proofs took 26.4–30.0% less time on round two (`c98af6e40`) than on round one (`03adf8d0c`) across three guests. Their combined SDK-client-plus-server peak RSS fell by 33.2–56.2%. Raw core proof time fell by 13.9–42.7%. The highest round-two peak across five guests and four modes in those sessions was 12.16 GiB.

On 25 November, all eight round-one CUDA allocation failures verified with 21.99–22.15 GiB of free device memory. Round two used less host memory in every matched retry. Six-shard SHA-256 finished faster in every mode. Eight-shard Fibonacci finished faster in both two-proof wrapping modes and slower in core and compressed. Three further rotated comparisons reproduced the Fibonacci slowdown. [Retry measurements](#retried-with-more-device-memory-on-25-november) · [Repeated Fibonacci comparisons](#default-height-follow-up-with-three-rotated-builds)

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

### Retried with more device memory on 25 November

After other applications closed, these sessions started with 21.99–22.15 GiB free on the RTX 4090. All eight previously failing round-one cases completed. Each row uses one fresh session per commit with the same guest, input and default shard limit. The SDK verified each proof. The installed release servers matched the archived SHA-256 hashes listed below.

| Guest | Core shards | Mode | Round 1 time | Round 2 time | Round 1 peak RSS | Round 2 peak RSS |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| SHA-256, 2 MiB | 6 | Core | 3.666 s | 3.556 s | 7.65 GiB | 5.20 GiB |
| SHA-256, 2 MiB | 6 | Compressed | 4.976 s | 4.638 s | 7.82 GiB | 5.29 GiB |
| SHA-256, 2 MiB | 6 | 2× Groth16 | 24.741 s | 19.746 s | 15.56 GiB | 9.44 GiB |
| SHA-256, 2 MiB | 6 | 2× PLONK | 33.136 s | 24.529 s | 14.74 GiB | 9.64 GiB |
| Fibonacci, 4,000,000 | 8 | Core | 3.912 s | 4.676 s | 9.29 GiB | 7.43 GiB |
| Fibonacci, 4,000,000 | 8 | Compressed | 5.855 s | 6.547 s | 9.41 GiB | 7.53 GiB |
| Fibonacci, 4,000,000 | 8 | 2× Groth16 | 25.598 s | 22.264 s | 17.82 GiB | 11.97 GiB |
| Fibonacci, 4,000,000 | 8 | 2× PLONK | 33.824 s | 28.369 s | 16.77 GiB | 12.06 GiB |

Round two used less combined host memory in all eight comparisons. On four-million-iteration Fibonacci, core took 0.764 s longer and compressed took 0.692 s longer. Both two-proof wrapping sessions finished faster. The CSV identifies these one-session runs as `reference-retry` and `candidate-retry`. [Individual session timings and RSS](sdk-proof-benchmark-trials.csv)

### Default-height follow-up with three rotated builds

The release CUDA servers used the same SDK client and default shard height of 4,194,304. Each cell gives median SDK proof time and the largest simultaneous SDK-plus-server peak RSS. Each Groth16 and PLONK session verified two proofs. The revised LogUp budget estimates per-round workspace before deciding whether to retain the main codeword. [LogUp PR](https://github.com/succinctlabs/sp1/pull/3052)

| Default-height guest | Mode | Sessions per build | Round 1 | Round 2 | Round 2 with revised LogUp budget |
| --- | --- | ---: | ---: | ---: | ---: |
| Fibonacci, 4,000,000 (8 shards) | Core | 3 | 3.799 s / 9.51 GiB | 4.870 s / 7.09 GiB | 4.417 s / 6.98 GiB |
| Fibonacci, 4,000,000 (8 shards) | Compressed | 3 | 5.711 s / 9.67 GiB | 6.928 s / 7.52 GiB | 6.745 s / 7.52 GiB |
| SHA-256, 2 MiB (6 shards) | 2× Groth16 | 1 | — | 18.822 s / 9.94 GiB | 18.419 s / 9.06 GiB |
| SHA-256, 2 MiB (6 shards) | 2× PLONK | 1 | — | 25.305 s / 9.92 GiB | 25.263 s / 9.88 GiB |
| Fibonacci, 4,000,000 (8 shards) | 2× Groth16 | 1 | — | 23.076 s / 11.87 GiB | 22.633 s / 11.86 GiB |
| Fibonacci, 4,000,000 (8 shards) | 2× PLONK | 3 | — | 30.813 s / 12.44 GiB | 30.490 s / 12.46 GiB |

<details><summary>Paired controls for the default-height Fibonacci slowdown</summary>

Two fresh sessions per mode and setting used the same instrumented round-two binary. Each control used the full round-two settings except in the last pair of rows, where both builds used two staging slots. The earlier ablation table documents the settings and their interactions. [Earlier ablations](sdk-proof-improvement-breakdown.md)

| Eight-shard Fibonacci configuration | Mode | Control | Changed | Median paired time saved | Median paired RSS saved |
| --- | --- | ---: | ---: | ---: | ---: |
| Regenerate dependency rows | Core | 5.182 s / 7.16 GiB | 5.169 s / 6.72 GiB | +0.013 s | +0.23 GiB |
| Regenerate dependency rows | Compressed | 7.372 s / 7.52 GiB | 7.329 s / 7.13 GiB | +0.043 s | +0.42 GiB |
| Recompute preprocessing | Core | 5.182 s / 7.16 GiB | 5.427 s / 7.06 GiB | -0.245 s | -0.11 GiB |
| Recompute preprocessing | Compressed | 7.372 s / 7.52 GiB | 7.497 s / 7.51 GiB | -0.125 s | +0.01 GiB |
| Serialize device admission | Core | 5.182 s / 7.16 GiB | 5.431 s / 7.06 GiB | -0.248 s | -0.16 GiB |
| Serialize device admission | Compressed | 7.372 s / 7.52 GiB | 7.071 s / 7.10 GiB | +0.301 s | +0.47 GiB |
| Original worker counts | Core | 5.182 s / 7.16 GiB | 5.306 s / 8.46 GiB | -0.123 s | -1.35 GiB |
| Original worker counts | Compressed | 7.372 s / 7.52 GiB | 6.773 s / 8.32 GiB | +0.599 s | -0.76 GiB |
| Reduce per-AIR staging to two slots | Core | 5.182 s / 7.16 GiB | 5.525 s / 7.20 GiB | -0.343 s | -0.31 GiB |
| Reduce per-AIR staging to two slots | Compressed | 7.372 s / 7.52 GiB | 7.126 s / 7.46 GiB | +0.246 s | +0.18 GiB |
| Two maximum-sized pinned buffers versus two per-AIR slots | Core | 5.525 s / 7.20 GiB | 4.927 s / 8.61 GiB | +0.599 s | -1.41 GiB |
| Two maximum-sized pinned buffers versus two per-AIR slots | Compressed | 7.126 s / 7.46 GiB | 6.290 s / 8.64 GiB | +0.836 s | -1.30 GiB |

</details>

### CUDA activity on eight-shard Fibonacci

Separate CUPTI captures recorded each installed server and mode. Durations are unions of overlapping intervals inside the SDK proof window. Host stream synchronization can overlap device execution. Round two waits for borrowed host copies to finish before the caller can reuse their memory. Round one predates that lifetime fix. Profiling adds overhead. [Host copy lifetime fix](https://github.com/succinctlabs/sp1/pull/3047)

| Profiled build | Mode | SDK proof time | Kernels or transfers active | Outside kernels and transfers | Host to device | Device to host | Host threads inside a stream synchronization |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| round1 | Core | 4.412 s | 2.077 s | 2.335 s | 6.61 GiB | 0.02 GiB | 0.000 s |
| round2 | Core | 5.746 s | 2.834 s | 2.912 s | 6.58 GiB | 0.02 GiB | 0.679 s |
| cuda-budget | Core | 5.172 s | 2.357 s | 2.815 s | 6.58 GiB | 0.02 GiB | 0.396 s |
| round2 | Compressed | 7.789 s | 3.600 s | 4.189 s | 7.78 GiB | 0.03 GiB | 1.014 s |
| round1 | Compressed | 6.583 s | 3.042 s | 3.541 s | 7.81 GiB | 0.03 GiB | 0.000 s |
| cuda-budget | Compressed | 7.731 s | 3.253 s | 4.478 s | 7.78 GiB | 0.03 GiB | 0.715 s |

CUPTI also recorded the size and duration of every individual host-to-device transfer inside the proof call. Summing the large transfers gives the following subset.

| Build | Mode | Uploads of at least 64 MiB | Total uploaded | Sum of upload durations |
| --- | --- | ---: | ---: | ---: |
| round1 | Core | 43 | 6.41 GiB | 0.486 s |
| round2 | Core | 43 | 6.41 GiB | 0.876 s |
| round1 | Compressed | 43 | 6.41 GiB | 0.481 s |
| round2 | Compressed | 43 | 6.41 GiB | 0.894 s |

### Batched NTT row count

The four shapes with the greatest cumulative NTT kernel time in the revised-budget profiles were replayed directly with its release CUDA object. Each timing is the median of five CUDA event measurements. Every output element matched a transform submitted one polynomial at a time. L2 limits give the size of the active rows relative to the measured device cache.

| Domain | Polynomials | Transform | Full batch | L2 / 2 |
| ---: | ---: | --- | ---: | ---: |
| 4,194,304 | 34 | Forward | 7.597 ms | 4.000 ms |
| 4,194,304 | 34 | Inverse | 4.226 ms | 2.749 ms |
| 4,194,304 | 52 | Forward | 6.889 ms | 4.265 ms |
| 4,194,304 | 52 | Inverse | 6.623 ms | 3.983 ms |
| 8,388,608 | 4 | Forward | 1.041 ms | 0.758 ms |
| 8,388,608 | 4 | Inverse | 1.038 ms | 0.719 ms |
| 8,388,608 | 136 | Forward | 34.334 ms | 21.237 ms |
| 8,388,608 | 136 | Inverse | 35.304 ms | 21.519 ms |

### Where the server waited on CUDA

A separate call-stack capture on round two recorded stream synchronizations lasting at least 150 microseconds. Wait time is the union of the intervals at each call site inside the SDK proof. A thread waiting here may be waiting for earlier kernels on the same stream.

| Round-two call site | Core calls | Core wait | Compressed calls | Compressed wait |
| --- | ---: | ---: | ---: | ---: |
| Upload zero-check dispatch descriptors | 168 | 0.235 s | 393 | 0.438 s |
| Read back the grinding witness | 6 | 0.239 s | 6 | 0.240 s |
| Generate the first LogUp layer | 14 | 0.090 s | 25 | 0.117 s |

Three rotated pairs per build measured the following local candidates at the same input and shard height.

| Eight-shard Fibonacci experiment | Mode | Revised LogUp budget | With additional change |
| --- | --- | ---: | ---: |
| Allocate page-locked storage for individual host traces of at least 64 MiB | Core | 5.095 s / 7.15 GiB | 7.676 s / 7.47 GiB |
| Allocate page-locked storage for individual host traces of at least 64 MiB | Compressed | 7.296 s / 7.51 GiB | 9.961 s / 7.70 GiB |

The installed release server hashes were round one `02e9d9aee8ef`, round two `fb40f2a31cdc`, and revised budget `318ea60fb907`. The SDK client hash was `b6c573ae9ff2`. [Individual trials](sdk-proof-benchmark-trials.csv)

### Intermediate PLONK repeat proof

The intermediate release server that kept the main trace codeword originally verified the first four-million-iteration Fibonacci proof in 21.098 s and exhausted device memory during its second proof. The archived server SHA-256 is `595e0b4d65e9ad492e1981ed7563df1fa1e22bffaad9e88efe4bba58351af6d4`. The retry started with 22.16 GiB of free VRAM. Both proofs verified in 15.076 s and 13.579 s, totaling 28.654 s. The SDK client and server together peaked at 12.51 GiB host RSS and the server peaked at 21.32 GiB of device memory.

### Native gnark PLONK on nine-shard Fibonacci

The original uncapped native gnark attempt on the Poseidon2 PR was killed by the Linux OOM killer near 44 GiB combined RSS. After memory was freed, a guard stopped a second attempt near 56.39 GiB. A third original-settings attempt ran without that guard in an isolated memory cgroup sized from available RAM, reserving 128 MiB. The kernel reported a memory-cgroup OOM and killed the GPU server.

| Build and Go runtime | Available RAM at launch | First proof | Repeat proof | Peak combined host RSS | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| Main, defaults | 57.10 GiB | — | — | 54.57 GiB | Kernel OOM at 56.98 GiB cgroup limit |
| #3050, defaults | 57.52 GiB | — | — | 56.38 GiB | Kernel OOM at 57.40 GiB cgroup limit |
| Main, lower heap | 57.63 GiB | 297.197 s | 300.123 s | 45.99 GiB | Verified |
| #3049, lower heap | 57.85 GiB | 295.608 s | 294.520 s | 45.22 GiB | Verified |
| #3050, lower heap | 57.56 GiB | 300.146 s | 294.029 s | 45.27 GiB | Verified |

A host OOM interrupted sampling. The failed rows give the highest observed simultaneous SDK and server RSS, a lower bound. At the kill the kernel separately reported server RSS of 56.83 GiB on main and 57.22 GiB on #3050.

The matched successful PLONK runs used `GOMEMLIMIT=23GiB GOGC=30 GOMAXPROCS=16`. Each row started with a fresh server. The successful rows include two successive calls.

### Earlier in-process core failures

The earlier in-process benchmark also exhausted CUDA memory on million-iteration Fibonacci at default height. The first two rows rerun the archived node binaries with their original CLI. Their RSS is the kernel process high-water mark. The CLI used `--program local-fibonacci --param 1000000 --mode core -n 1`. The other rows use the SDK and installed server on the same guest and report simultaneous RSS. The SDK core proofs had 3 shards.

| Build and entry point | Core proof | Peak host RSS |
| --- | ---: | ---: |
| Original baseline, in-process | 1.674 s | 11.93 GiB |
| Archived first-round candidate (v6), in-process | 1.276 s | 7.07 GiB |
| Original CUDA PR, SDK and installed server | 1.584 s | 12.41 GiB |
| Round 1, SDK and installed server | 1.449 s | 6.46 GiB |
| Round 2, SDK and installed server | 1.444 s | 4.64 GiB |

<details><summary>Five other allocation failures found in the tuning logs</summary>

These one-session controls used the archived release servers and the same archived SDK binary. The SHA-256 input produced eight shards. The three-worker PLONK pilot used 16 Rayon threads and the original three core workers. The early Fibonacci core log labels its input `fib2m`. The retry used 2,000,000 iterations at the default shard height.

| Archived server (SHA-256 prefix) | Guest | Mode | Original outcome | Free VRAM at retry | Retry first / repeat | Peak host RSS | Retry outcome |
| --- | --- | --- | --- | ---: | ---: | ---: | --- |
| Earlier shard scheduling (`82875aadece1`) | Fibonacci, 2,000,000 | Core | CUDA OOM before first proof | 22.15 GiB | 2.435 s | 7.08 GiB | Verified |
| SHA-256 scheduling build Y (`da26a63e9566`) | SHA-256, 1 MiB | 2× Groth16 | Repeat CUDA OOM after 11.189 s first proof | 22.15 GiB | 9.460 s / 6.808 s | 11.70 GiB | Verified |
| SHA-256 scheduling build Z (`44f86b3fdde1`) | SHA-256, 1 MiB | 2× Groth16 | Repeat CUDA OOM after 11.688 s first proof | 22.15 GiB | 9.134 s / 6.661 s | 11.43 GiB | Verified |
| Three-worker tuning run (`8626f5e98eca`) | Fibonacci, 4,000,000 | 2× PLONK | Repeat CUDA OOM after 20.071 s first proof | 22.15 GiB | 15.293 s / 13.779 s | 11.70 GiB | Verified |
| Earlier CUDA stream startup (`6b7cd17832cd`) | Fibonacci, 4,000,000 | Compressed | CUDA OOM at startup | 22.15 GiB | 6.121 s | 8.31 GiB | Verified |

</details>

## Prover changes

Groth16 streams large proving-key tables through bounded pinned host buffers. PLONK and Groth16 overlap key preparation with the STARK prover. Core shards reuse immutable program preprocessing and allocate host traces per AIR. The GPU prover estimates host and device workspace before admitting concurrent shards. When a large LogUp proof needs the memory occupied by an encoded trace, the prover releases it and re-encodes it for the FRI opening. Batched transforms, Merkle tree compression and direct FRI folding reduce GPU work.

Four repeated CPU/GPU transform comparisons passed under NVIDIA Compute Sanitizer. Twelve additional eight-shard SHA-256 compressed proofs verified with six core workers and 24 Rayon threads. These stress runs are separate from the performance trials.

## Measurement conditions

Within each comparison, the same release SDK client launched the installed `~/.sp1/bin/sp1-gpu-server` for each trial. Each proof was independently verified by the SDK. A monotonic clock bracketed each `prove` call. SDK setup and independent verification fall outside those timers. The two-proof total includes both the first and repeat calls. The GPU server process and its proving-key cache started fresh in every session. Installed circuit files used the operating system’s normal page cache.

The sampler read resident pages for both PIDs from `/proc/<pid>/statm` and slept 4 ms between observations. It took the maximum of the simultaneous sum over setup, proving, verification and shutdown. Linux counts shared resident pages toward each process. GPU device memory is separate. Measurements cover the supplied guests, inputs and hardware.

The GPU had 17.86 to 19.60 GiB of device memory free at the start of the 24 November sessions.

The highest optimized sample occurred during the 24 November Fibonacci, 4,000,000 run in 2× PLONK mode. The client accounted for 48.7 MiB and the server accounted for 12.113 GiB.

Including transient helpers in the SDK process group, the highest observed optimized peak was 12.16 GiB. The trial data also records wall time from client launch through exit.

The runner rotated workload order and alternated which build ran first. A preflight required at least 75% idle CPU capacity and 70% free GPU memory. Sessions with more than eight logical CPUs of external load on average or more than sixteen in two consecutive one-second samples were excluded and repeated. The per-session CSV includes all accepted successes and the baseline GPU allocation failures for the default-size workloads. Individual first and repeat times, the RSS sample’s two components and host load are available in the [trial data](sdk-proof-benchmark-trials.csv).

| Item | Value |
| --- | --- |
| GPU | GeForce RTX 4090, 24,564 MiB |
| CPU | AMD Ryzen 9 5950X, 16 cores / 32 threads |
| Software | Linux 7.2.9, NVIDIA 615.71.09, CUDA 13.4.92, SP1 circuits v6.1.0 |
| Reference server SHA-256 | `02e9d9aee8ef282fd16a420afcd17b8cefc7ca0e8039e65f3c0d97a3c53ab06c` |
| Optimized server SHA-256 | `fb40f2a31cdc337eb724426c82bf103b9756e7f7c79ceb0f6c2363b01351c87a` |
| 24 November SDK runner SHA-256 | `0b4369451fcdbcec2f693e85a82f2b2d9388bacf8b2afa5f60704cbc9d502e64` |
| 25 November SDK runner SHA-256 | `e707bf90474e68ebc6e6b173304ac968d46f9f45e00afca2ab273635187bd0f0` |
| Source patch SHA-256 | `7e9a0f0b18624afd9c1724fce1d472be0e61ef334be4c76409bf0def2748b8f4` |

The accompanying evidence archive includes the reproducible source patch, sampler, SDK runner, build hashes, per-sample RSS and verification logs.

The follow-up benchmarks measured individual changes in both prover commits for each proof mode. [Per-change timings and peak RSS](sdk-proof-improvement-breakdown.md)

The main-branch PR comparisons re-executed an Ethereum block at 36 and 102 core shards. [RSP timings and combined peak RSS](sdk-rsp-pr-benchmarks.md)
