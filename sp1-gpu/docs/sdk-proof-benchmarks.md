# SDK and CUDA server proof benchmarks

On 24 November 2026, compressed proofs and pairs of Groth16 or PLONK proofs took 26.4–30.0% less time on round two (`c98af6e40`) than on round one (`03adf8d0c`) across three guests. Their combined SDK-client-plus-server peak RSS fell by 33.2–56.2%. Raw core proof time fell by 13.9–42.7%. The highest round-two peak across five guests and four modes in those sessions was 12.16 GiB.

On 25 November, all eight round-one CUDA allocation failures verified with 21.99–22.15 GiB of free device memory. Round two used less host memory in every matched retry. Six-shard SHA-256 finished faster in every mode. Eight-shard Fibonacci finished faster in both two-proof wrapping modes and slower in core and compressed. Three further rotated comparisons reproduced the Fibonacci slowdown. [Retry measurements](#retried-with-more-device-memory-on-25-november) · [Repeated Fibonacci comparisons](#default-height-follow-up-with-three-rotated-builds)

Six earlier SDK tuning sessions that had exhausted device memory also verified, bringing the total to **14 of 14 CUDA SDK retries**. Both archived in-process core commands completed. Native gnark PLONK on nine-shard Fibonacci still hit the host memory limit with Go defaults on main and #3050. With a 23 GiB Go heap target, main, #3049 and #3050 each verified two proofs at 45.22–45.99 GiB combined host RSS. [Intermediate and in-process retries](#intermediate-plonk-repeat-proof) · [Native PLONK measurements](#native-gnark-plonk-on-nine-shard-fibonacci)

Round two and the host trace admission candidate each verified all 50 sessions in a six-guest comparison that included 102-shard RSP. The sum of median proof times fell from 499.826 to 471.068 s and the highest observed combined RSS fell from 12.45 to 11.94 GiB. Five-pair checks found peak increases of 13.5–25.5 MiB on three guest and mode combinations. The benchmark branch uses the measured round-two release. [Six-guest results](#selected-cuda-follow-up) · [Repeated comparisons](#confirmation-of-increases-in-the-two-initial-rotations)

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

The eight sessions together took 135.709 s in round one and 114.325 s in round two (15.8% less proof time). The largest combined host RSS fell from 17.82 to 12.06 GiB (32.3% lower). Round two used less combined host memory in all eight comparisons. On four-million-iteration Fibonacci, core took 0.764 s longer and compressed took 0.692 s longer. Both two-proof wrapping sessions finished faster. The CSV identifies these one-session runs as `reference-retry` and `candidate-retry`. [Individual session timings and RSS](sdk-proof-benchmark-trials.csv)

A later run of the same round-one Fibonacci core proof started with 20.37 GiB of free VRAM. The server failed a 610.5 MiB tensor allocation before returning a proof. Combined host RSS had reached 9.92 GiB. The successful run above started with 21.99 GiB of free VRAM. The failed run ended before an allocation backtrace was captured. A separate retry with allocation backtraces started with 19.95 GiB free on the device and 44.90 GiB available on the host. A 1.19 GiB device allocation failed in the LogUp GKR layer transition. Combined host RSS had reached 9.85 GiB.

#### Repeated eight-shard Fibonacci at lower device headroom

On the original round-one server, all three core and all three compressed sessions failed the same 1.19 GiB device allocation in the LogUp GKR layer transition. Those six sessions started with 19.71–20.03 GiB free on the RTX 4090. Round two and the revised LogUp budget with separate host admission and later CPU row generation (`510c8ad0a`) verified all six sessions apiece. The three builds rotated on one workstation.

| Mode | Round one | Round two, time / peak RSS | Revised build, time / peak RSS |
| --- | --- | ---: | ---: |
| Core | 3 CUDA OOMs | 6.697 s / 7.38 GiB | 6.358 s / 6.98 GiB |
| Compressed | 3 CUDA OOMs | 9.622 s / 7.48 GiB | 8.057 s / 7.04 GiB |

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

Three rotated pairs per build measured each candidate at the same input and shard height. Median external CPU use was 0.4 logical cores during the separate-admission comparison and 2.9 during the addition-lookup comparison. Each row has its own contemporaneous control.

| Eight-shard Fibonacci experiment | Mode | Revised LogUp budget | With additional change |
| --- | --- | ---: | ---: |
| Separate large host trace and device admission | Core | 5.245 s / 7.16 GiB | 5.145 s / 7.17 GiB |
| Separate large host trace and device admission | Compressed | 7.298 s / 7.50 GiB | 6.388 s / 7.45 GiB |
| Merge addition byte counts before hash insertion | Core | 6.514 s / 7.32 GiB | 6.446 s / 7.32 GiB |
| Merge addition byte counts before hash insertion | Compressed | 9.453 s / 7.47 GiB | 9.197 s / 7.47 GiB |
| Fence a group of ready AIR uploads once | Core | 6.771 s / 7.31 GiB | 6.727 s / 7.39 GiB |
| Fence a group of ready AIR uploads once | Compressed | 9.871 s / 7.44 GiB | 9.752 s / 7.52 GiB |
| Generate integer multiplication rows without temporary vectors | Core | 6.453 s / 7.34 GiB | 6.480 s / 7.35 GiB |
| Generate integer multiplication rows without temporary vectors | Compressed | 9.273 s / 7.48 GiB | 9.313 s / 7.52 GiB |
| Expand the multiplication columns directly on the GPU | Core | 6.567 s / 7.39 GiB | 6.385 s / 7.27 GiB |
| Expand the multiplication columns directly on the GPU | Compressed | 9.658 s / 7.46 GiB | 9.564 s / 7.30 GiB |
| Limit each batch of NTT rows to a fraction of device cache | Core | 4.959 s / 6.85 GiB | 5.079 s / 7.18 GiB |
| Limit each batch of NTT rows to a fraction of device cache | Compressed | 6.972 s / 7.54 GiB | 7.005 s / 7.52 GiB |
| Allocate page-locked storage for individual host traces of at least 64 MiB | Core | 5.095 s / 7.15 GiB | 7.676 s / 7.47 GiB |
| Allocate page-locked storage for individual host traces of at least 64 MiB | Compressed | 7.296 s / 7.51 GiB | 9.961 s / 7.70 GiB |
| Upload the sequential and GKR dispatch tables once per zero-check round | Core | 6.854 s / 7.33 GiB | 6.848 s / 7.36 GiB |
| Upload the sequential and GKR dispatch tables once per zero-check round | Compressed | 9.735 s / 7.46 GiB | 9.582 s / 7.44 GiB |

### Multiplication trace generation on three guests

In a captured four-million-iteration Fibonacci shard the multiplication trace contained 105,455,936 field elements. In a captured RSP shard it contained 556,288. Round two can retain multiplication rows during CPU dependency generation when they fit the 67,108,864-element retention budget. The GPU path consumes event operands. Main generates the CPU rows on demand. A CUDA kernel expands the signed or unsigned multiplication witness columns from each event’s operands. The release GPU test matched the CPU trace for all five opcodes, both trust modes and six event counts including zero. NVIDIA Compute Sanitizer memcheck reported zero errors. The table uses separate verified SDK proof sessions.

| Guest | Mode | Paired sessions | Revised LogUp budget | GPU multiplication trace |
| --- | --- | ---: | ---: | ---: |
| Fibonacci, 4,000,000 | Core | 3 | 6.567 s / 7.39 GiB | 6.385 s / 7.27 GiB |
| Fibonacci, 4,000,000 | Compressed | 3 | 9.658 s / 7.46 GiB | 9.564 s / 7.30 GiB |
| Ethereum RSP, block 21,740,136 | Core | 3 | 26.207 s / 5.40 GiB | 26.242 s / 5.72 GiB |
| Ethereum RSP, block 21,740,136 | Compressed | 3 | 40.714 s / 5.66 GiB | 40.219 s / 5.80 GiB |
| SHA-256, 1 MiB | Core | 2 | 2.424 s / 3.68 GiB | 2.523 s / 3.70 GiB |
| SHA-256, 1 MiB | Compressed | 2 | 4.212 s / 3.99 GiB | 4.226 s / 3.90 GiB |

A separate port at `27f3f771f` ran against main at `0cd151a8d`, where CPU rows are generated on demand. The port passed the same whole-trace comparison and Compute Sanitizer memcheck. Both builds used SDK client `013b2ecf88ac` for RSP and `e707bf90474e` for the smaller guests.

| Guest on main | Mode | Paired sessions | Main | GPU multiplication trace |
| --- | --- | ---: | ---: | ---: |
| Ethereum RSP, block 21,740,136 | Core | 3 | 31.033 s / 12.73 GiB | 27.412 s / 12.68 GiB |
| Ethereum RSP, block 21,740,136 | Compressed | 3 | 42.862 s / 13.56 GiB | 42.724 s / 13.39 GiB |
| SHA-256, 1 MiB | Core | 2 | 2.654 s / 11.61 GiB | 2.516 s / 11.66 GiB |
| SHA-256, 1 MiB | Compressed | 2 | 4.063 s / 12.12 GiB | 4.074 s / 12.15 GiB |

The same GPU multiplication kernel was also measured on the CUDA branch after CPU row generation moved to the host-admission stage. The control was `510c8ad0a` and the kernel build was `9bf0644b9`. Both used the same SDK client.

| Guest | Mode | Paired sessions | CPU trace after admission | GPU multiplication after admission |
| --- | --- | ---: | ---: | ---: |
| Ethereum RSP, block 21,740,136 | Core | 3 | 22.650 s / 5.61 GiB | 23.016 s / 5.57 GiB |
| Ethereum RSP, block 21,740,136 | Compressed | 3 | 37.604 s / 5.33 GiB | 37.572 s / 5.78 GiB |

### When to generate the CPU trace rows

Three rotated sets on eight-shard Fibonacci compared the revised device budget, separate host admission, and generating the rows after host admission. The third build collects byte lookups in the dependency pass and generates each trace when the GPU trace pipeline requests it.

| Mode | Revised budget | Separate host admission | Separate admission and generate rows later |
| --- | ---: | ---: | ---: |
| Core | 6.138 s / 7.35 GiB | 5.859 s / 7.33 GiB | 5.739 s / 6.96 GiB |
| Compressed | 8.774 s / 7.45 GiB | 7.740 s / 7.40 GiB | 7.579 s / 6.99 GiB |

### Allocator arenas after host trace admission

Three rotated sessions per setting used the same follow-up server and SDK binaries. The four-arena setting used `_RJEM_MALLOC_CONF=narenas:4`. Jemalloc configuration output confirmed the override. Both follow-up settings used background purging with 250 ms dirty and muzzy page decay.

| Guest | Mode | Round one | Follow-up, eight arenas | Follow-up, four arenas |
| --- | --- | ---: | ---: | ---: |
| Ethereum RSP, block 21,740,136 | Core | 26.959 s / 6.67 GiB | 19.979 s / 5.45 GiB | 20.880 s / 5.49 GiB |

### Rayon pool size after host trace admission

The control server used its default of one Rayon thread per physical core. The alternative set `RAYON_NUM_THREADS=12` when launching the SDK and server. Three alternating pairs used the same release binaries and default allocator settings.

| Guest | Mode | 16 server Rayon threads | 12 Rayon threads |
| --- | --- | ---: | ---: |
| Ethereum RSP, block 21,740,136 | Core | 20.855 s / 5.58 GiB | 21.263 s / 5.63 GiB |

### Core prover workers at the smaller shard height

At height 262,144 the follow-up server used five CPU core-proving workers, four trace staging slots and 24 permits for device workspace. The alternative used `SP1_WORKER_NUM_CORE_WORKERS=4` on the same release. The default settings of both original rounds ran in the same four RSP core rotations.

| Guest | Mode | Sessions per setting | Round one | Round two | Follow-up, five workers | Follow-up, four workers |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Ethereum RSP, block 21,740,136 | Core | 4 | 26.466 s / 6.60 GiB | 23.109 s / 5.64 GiB | 21.642 s / 5.69 GiB | 22.619 s / 5.16 GiB |

### Core worker and Rayon settings

The same installed revised-budget binary ran three rotated sessions per mode at each setting. The machine has 16 physical cores and 32 logical CPUs.

| Core workers | Rayon threads | Core median / maximum RSS | Compressed median / maximum RSS |
| ---: | ---: | ---: | ---: |
| 3 | 16 | 7.001 s / 7.37 GiB | 9.777 s / 7.47 GiB |
| 4 | 16 | 6.359 s / 9.10 GiB | 8.920 s / 9.15 GiB |
| 3 | 32 | 6.995 s / 7.45 GiB | 9.908 s / 7.50 GiB |
| 4 | 32 | 6.650 s / 9.16 GiB | 9.048 s / 9.20 GiB |

The installed release server hashes were round one `02e9d9aee8ef`, round two `fb40f2a31cdc`, and revised budget `318ea60fb907`. Those comparisons used SDK client `b6c573ae9ff2`. [Individual trials](sdk-proof-benchmark-trials.csv)

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

## Reviewed CUDA changes on eight-shard SHA-256

The local integration at `e48fb00ce` applied 9 independent PRs to the CUDA wrapper at `92d01c0cd`. The original CUDA PR at `6f14261e8` served as the control. Each installed release ran one fresh session per mode with the same SDK client. The SHA-256 guest hashed one MiB at a shard height of 262,144. [#3046](https://github.com/succinctlabs/sp1/pull/3046) · [#3047](https://github.com/succinctlabs/sp1/pull/3047) · [#3048](https://github.com/succinctlabs/sp1/pull/3048) · [#3049](https://github.com/succinctlabs/sp1/pull/3049) · [#3050](https://github.com/succinctlabs/sp1/pull/3050) · [#3051](https://github.com/succinctlabs/sp1/pull/3051) · [#3052](https://github.com/succinctlabs/sp1/pull/3052) · [#3054](https://github.com/succinctlabs/sp1/pull/3054) · [#3055](https://github.com/succinctlabs/sp1/pull/3055)

Each cell gives SDK proof time and simultaneous client-plus-server peak RSS. Groth16 and PLONK each proved the input twice. [All four modes on the 102-shard RSP block](sdk-rsp-pr-benchmarks.md#published-changes-together)

| Mode | Original CUDA PR | Combined review branches | Time saved | Peak RSS saved |
| --- | ---: | ---: | ---: | ---: |
| Core | 2.636 s / 11.65 GiB | 2.318 s / 9.45 GiB | 12.1% | 18.9% |
| Compressed | 4.116 s / 11.97 GiB | 3.944 s / 9.72 GiB | 4.2% | 18.8% |
| 2× Groth16 | 33.160 s / 19.89 GiB | 23.340 s / 12.98 GiB | 29.6% | 34.7% |
| 2× PLONK | 38.255 s / 18.74 GiB | 30.299 s / 13.58 GiB | 20.8% | 27.5% |

Across the four sessions, proof time totaled 78.167 s before and 59.900 s with the review changes (23.4% saved). The largest combined host RSS went from 19.89 to 13.58 GiB.

## Selected CUDA follow-up

The follow-up at `510c8ad0a` estimates the LogUp workspace before retaining a codeword, reserves host memory separately for a large trace and generates CPU rows after collecting the byte lookups. Each cell gives median SDK proof time and the largest simultaneous client-plus-server host RSS. A wrapping session includes both verified proofs. The three builds ran in rotating order with the release server installed in `~/.sp1/bin`.

| Guest | Mode | Sessions per build | Round 1 | Round 2 | Follow-up | Time saved vs. round 1 | RSS saved vs. round 1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fibonacci 4,000,000 (8 shards) | Core | 3 | CUDA OOM | 6.697 s / 7.38 GiB | 6.358 s / 6.98 GiB | — | — |
| Fibonacci 4,000,000 (8 shards) | Compressed | 3 | CUDA OOM | 9.622 s / 7.48 GiB | 8.057 s / 7.04 GiB | — | — |
| Fibonacci 4,000,000 (8 shards) | 2× Groth16 | 2 | CUDA OOM | 26.834 s / 11.86 GiB | 24.356 s / 11.44 GiB | — | — |
| Fibonacci 4,000,000 (8 shards) | 2× PLONK | 2 | CUDA OOM | 33.830 s / 12.45 GiB | 31.653 s / 11.94 GiB | — | — |
| SHA-256 1 MiB (8 shards) | Core | 2 | 2.701 s / 5.57 GiB | 2.010 s / 3.45 GiB | 1.982 s / 3.63 GiB | 26.6% | 34.8% |
| SHA-256 1 MiB (8 shards) | Compressed | 2 | 4.220 s / 6.15 GiB | 3.331 s / 3.73 GiB | 3.219 s / 3.61 GiB | 23.7% | 41.2% |
| SHA-256 1 MiB (8 shards) | 2× Groth16 | 2 | 23.962 s / 14.52 GiB | 17.334 s / 8.53 GiB | 16.373 s / 8.29 GiB | 31.7% | 42.9% |
| SHA-256 1 MiB (8 shards) | 2× PLONK | 2 | 34.833 s / 13.13 GiB | 24.082 s / 8.25 GiB | 23.414 s / 7.76 GiB | 32.8% | 40.9% |
| Fibonacci 1,000,000 (9 shards) | Core | 2 | 1.900 s / 5.18 GiB | 1.771 s / 3.91 GiB | 1.592 s / 3.24 GiB | 16.2% | 37.4% |
| Fibonacci 1,000,000 (9 shards) | Compressed | 2 | 3.780 s / 5.73 GiB | 2.965 s / 3.85 GiB | 2.675 s / 3.54 GiB | 29.2% | 38.2% |
| Fibonacci 1,000,000 (9 shards) | 2× Groth16 | 2 | 22.165 s / 14.02 GiB | 16.180 s / 8.92 GiB | 15.515 s / 8.68 GiB | 30.0% | 38.1% |
| Fibonacci 1,000,000 (9 shards) | 2× PLONK | 2 | 31.898 s / 12.62 GiB | 23.045 s / 8.18 GiB | 22.606 s / 8.19 GiB | 29.1% | 35.1% |
| Fibonacci 1,000 (2 shards) | Core | 2 | 0.402 s / 3.90 GiB | 0.163 s / 1.53 GiB | 0.169 s / 1.53 GiB | 57.9% | 60.9% |
| Fibonacci 1,000 (2 shards) | Compressed | 2 | 0.946 s / 4.23 GiB | 0.695 s / 1.86 GiB | 0.716 s / 1.85 GiB | 24.4% | 56.3% |
| Fibonacci 1,000 (2 shards) | 2× Groth16 | 2 | 16.930 s / 13.55 GiB | 11.104 s / 6.76 GiB | 11.206 s / 6.79 GiB | 33.8% | 49.9% |
| Fibonacci 1,000 (2 shards) | 2× PLONK | 2 | 26.432 s / 12.16 GiB | 19.273 s / 6.81 GiB | 19.723 s / 6.81 GiB | 25.4% | 44.0% |
| SHA-256 2 MiB (6 shards) | Core | 2 | CUDA OOM | 4.833 s / 5.08 GiB | 4.170 s / 4.91 GiB | — | — |
| SHA-256 2 MiB (6 shards) | Compressed | 2 | CUDA OOM | 6.139 s / 5.13 GiB | 5.523 s / 4.86 GiB | — | — |
| SHA-256 2 MiB (6 shards) | 2× Groth16 | 2 | 31.401 s / 15.26 GiB (1/2 verified) | 22.788 s / 9.71 GiB | 22.076 s / 9.43 GiB | — | — |
| SHA-256 2 MiB (6 shards) | 2× PLONK | 2 | CUDA OOM | 31.370 s / 10.28 GiB | 29.733 s / 10.11 GiB | — | — |
| Ethereum RSP (102 shards) | Core | 2 | 24.796 s / 6.72 GiB | 22.097 s / 5.51 GiB | 20.438 s / 5.53 GiB | 17.6% | 17.8% |
| Ethereum RSP (102 shards) | Compressed | 2 | 51.349 s / 7.81 GiB | 36.835 s / 6.27 GiB | 33.143 s / 5.41 GiB | 35.5% | 30.7% |
| Ethereum RSP (102 shards) | 2× Groth16 | 2 | 124.513 s / 14.78 GiB | 85.062 s / 8.66 GiB | 80.280 s / 8.35 GiB | 35.5% | 43.5% |
| Ethereum RSP (102 shards) | 2× PLONK | 2 | 132.691 s / 14.46 GiB | 91.766 s / 9.94 GiB | 86.091 s / 9.68 GiB | 35.1% | 33.1% |

The RTX 4090 had 19.15–20.13 GiB of free device memory at launch across these 150 sessions.

CUDA allocation failures occurred at 19.36–20.04 GiB of free device memory at launch (17 on round1). Backtraces identified allocations in the LogUp GKR layer transition in 17 sessions (2 × 63.0 MiB, 2 × 125.8 MiB, 3 × 251.5 MiB, 2 × 610.5 MiB, 7 × 1,220.8 MiB, 1 × 1,220.9 MiB).

During the round-two and follow-up RSP sessions, NVIDIA process telemetry sampled other applications every two seconds while the proving server was visible on the GPU. Summed streaming-multiprocessor utilization for those applications averaged 19–26% per session on the control and 18–26% on the changed build.

The follow-up verified 50 of 50 SDK sessions. Of 16 fully paired guest/mode comparisons, 14 reached a further 20% time reduction from round one, 15 reached a further 20% RSS reduction, and 16 peaked below 16 GiB. The largest observed peak across all successful follow-up sessions was 11.94 GiB.

A guest meets all three targets when proof time and peak RSS both fall at least 20% from round one and peak RSS stays below 16 GiB. The round-two comparison includes every guest and mode where round two and the follow-up verified all repetitions, including cases where round one exhausted device memory. It sums median session times and takes the largest measured host RSS.

| Proof mode | All three targets vs. round 1 | Faster with equal or lower peak RSS vs. round 2 | Round 2 time / maximum RSS | Follow-up time / maximum RSS | Time saved vs. round 2 | Peak RSS saved vs. round 2 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Core | 2/4 | 3/6 | 37.569 s / 7.38 GiB | 34.710 s / 6.98 GiB | 7.6% | 5.4% |
| Compressed | 4/4 | 5/6 | 59.587 s / 7.48 GiB | 53.331 s / 7.04 GiB | 10.5% | 5.9% |
| 2× Groth16 | 4/4 | 5/6 | 179.302 s / 11.86 GiB | 169.807 s / 11.44 GiB | 5.3% | 3.5% |
| 2× PLONK | 4/4 | 4/6 | 223.368 s / 12.45 GiB | 213.220 s / 11.94 GiB | 4.5% | 4.1% |
| All modes | 14/16 | 17/24 | 499.826 s / 12.45 GiB | 471.068 s / 11.94 GiB | 5.8% | 4.1% |

### Time for the matched workload suite

Each verified guest contributes one core proof, one compressed proof, or two successive wrapping proofs for the indicated mode. The table sums the median session times and takes the largest observed combined host RSS. It includes a guest and mode only when all three builds verified every repetition. The individual table above reports the allocation failures and the measurements available on those guests.

| Mode | Guest/mode comparisons | Round 1 time / maximum RSS | Round 2 time / maximum RSS | Follow-up time / maximum RSS | Time saved vs. round 1 | Peak RSS saved vs. round 1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Core | 4 | 29.800 s / 6.72 GiB | 26.040 s / 5.51 GiB | 24.182 s / 5.53 GiB | 18.9% | 17.8% |
| Compressed | 4 | 60.294 s / 7.81 GiB | 43.827 s / 6.27 GiB | 39.752 s / 5.41 GiB | 34.1% | 30.7% |
| 2× Groth16 | 4 | 187.570 s / 14.78 GiB | 129.680 s / 8.92 GiB | 123.375 s / 8.68 GiB | 34.2% | 41.3% |
| 2× PLONK | 4 | 225.854 s / 14.46 GiB | 158.167 s / 9.94 GiB | 151.834 s / 9.68 GiB | 32.8% | 33.1% |
| All modes | 16 | 503.518 s / 14.78 GiB | 357.713 s / 9.94 GiB | 339.143 s / 9.68 GiB | 32.6% | 34.5% |

### Confirmation of increases in the two initial rotations

A further three alternating pairs repeated every guest and mode with higher median proof time or higher peak RSS on the follow-up than on round two. The table pools the initial and additional pairs. Each build contributes the same number of sessions. The final columns count the individual paired wins.

| Guest | Mode | Pairs | Round 2 | Follow-up | Pairs faster | Pairs with lower RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| SHA-256 1 MiB (8 shards) | Core | 5 | 2.087 s / 3.65 GiB | 1.906 s / 3.63 GiB | 4/5 | 4/5 |
| Fibonacci 1,000,000 (9 shards) | 2× PLONK | 5 | 24.468 s / 8.18 GiB | 24.311 s / 8.19 GiB | 4/5 | 3/5 |
| Fibonacci 1,000 (2 shards) | Core | 5 | 0.216 s / 1.53 GiB | 0.204 s / 1.53 GiB | 3/5 | 3/5 |
| Fibonacci 1,000 (2 shards) | Compressed | 5 | 0.791 s / 1.86 GiB | 0.756 s / 1.85 GiB | 2/5 | 2/5 |
| Fibonacci 1,000 (2 shards) | 2× Groth16 | 5 | 11.891 s / 6.76 GiB | 11.798 s / 6.79 GiB | 3/5 | 1/5 |
| Fibonacci 1,000 (2 shards) | 2× PLONK | 5 | 20.060 s / 6.83 GiB | 19.856 s / 6.81 GiB | 4/5 | 2/5 |
| Ethereum RSP (102 shards) | Core | 5 | 22.386 s / 5.57 GiB | 20.949 s / 5.59 GiB | 5/5 | 2/5 |

With the confirmation runs included, median proof time fell in 24 of 24 guest/mode comparisons against round two. Peak RSS was equal or lower in 21 of 24. Larger measured peaks were Fibonacci 1,000,000 (9 shards), 2× PLONK (+13.5 MiB), Fibonacci 1,000 (2 shards), 2× Groth16 (+25.5 MiB), Ethereum RSP (102 shards), Core (+14.9 MiB). The benchmark branch uses the round-two runtime.

The SDK client SHA-256 was `b6c573ae9ff2b2bc565c683018da6e35a0023088c806e795463e3ebe6e40f7e9` and the follow-up server SHA-256 was `de1862df2f58c7c9df0a31ceb01d0929b4d22afca185f9e6169eee0c45054906`. [Individual proof calls and RSS components](sdk-proof-benchmark-trials.csv)

## CPU row reuse for programs with one execution shard

Build `94fc86423` keeps the follow-up host-admission policy and reuses CPU trace rows when execution starts and halts in the same shard. The three builds ran in rotating order with the same SDK client.

| Guest | Mode | Sessions per build | Round two | Rows after host admission | Reuse rows for one execution shard |
| --- | --- | ---: | ---: | ---: | ---: |
| Fibonacci, 1,000 | Compressed | 3 | 0.756 s / 1.81 GiB | 0.763 s / 1.85 GiB | 0.768 s / 1.83 GiB |

The two-shard Fibonacci core proof had one execution shard with 14,966 CPU events and one shard with zero CPU events. Reading the serialized records confirmed that only the execution shard matched the reuse condition.

The single-execution change took 12.4 ms longer and used 21.9 MiB more peak host RSS than round two on this input.

The installed release server SHA-256 was `448563595580c4aaeb0b9eaeac7b051f31359b863ef176149353da35faf915a1`. [Individual proof calls and peak RSS](sdk-proof-benchmark-trials.csv)
