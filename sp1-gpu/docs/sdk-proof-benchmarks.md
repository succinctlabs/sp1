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
