# Proof time and peak RSS across two CUDA prover commits

Measured on 24–25 November 2026 (Europe/Oslo). Round 1 compares `03adf8d0c` with its parent `6f14261e8`. Round 2 compares `c98af6e40` with `03adf8d0c`. The SDK independently verified 783 proofs in 492 primary sessions. The individual-change tables cover 97 comparisons across four proof modes.

Across the two-, eight- and nine-shard guests, round 2 reduced compressed, Groth16 and PLONK proof time by 23.8–31.1% and simultaneous SDK-client-plus-server peak RSS by 32.6–55.9%. Raw core time fell by 17.7% on eight shards and 16.9% on nine. The highest round-two stock peak in this comparison was 9.00 GiB. The earlier default-shard-height comparison reached 12.16 GiB on a larger guest.

The measured effects file gives the paired percentage savings, three-pair ranges, first and repeat SNARK proof timings, and enabled and disabled values for each change. The session file gives the individual times, RSS components and installed server hashes. [Measured effects](sdk-proof-improvement-effects.csv) · [Individual sessions](sdk-proof-improvement-trials.csv)

## Commit totals

Each entry uses three fresh SDK sessions per commit. Time is the median proof-call duration. Peak RSS is the largest simultaneous client-plus-server sample across the three sessions. Percent reductions use the immediately preceding commit as the denominator.

### SHA-256 1 MiB · 8 core shards

| Mode | Parent time / peak | Round 1 time / peak | Round 2 time / peak | Round 1 reduction, time / RSS | Round 2 reduction, time / RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| Core | 3.014 s / 11.77 GiB | 2.818 s / 5.88 GiB | 2.319 s / 3.97 GiB | 6.5% / 50.1% | 17.7% / 32.5% |
| Compressed | 4.996 s / 12.14 GiB | 4.949 s / 6.56 GiB | 3.772 s / 4.26 GiB | 0.9% / 46.0% | 23.8% / 35.0% |
| 2× Groth16 | 32.071 s / 20.49 GiB | 26.510 s / 14.82 GiB | 19.376 s / 8.64 GiB | 17.3% / 27.7% | 26.9% / 41.7% |
| 2× PLONK | 47.738 s / 18.86 GiB | 36.414 s / 13.45 GiB | 27.465 s / 8.06 GiB | 23.7% / 28.7% | 24.6% / 40.0% |

### Fibonacci 1,000,000 · 9 core shards

| Mode | Parent time / peak | Round 1 time / peak | Round 2 time / peak | Round 1 reduction, time / RSS | Round 2 reduction, time / RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| Core | 2.278 s / 11.21 GiB | 2.083 s / 5.22 GiB | 1.732 s / 3.78 GiB | 8.5% / 53.4% | 16.9% / 27.6% |
| Compressed | 4.589 s / 11.82 GiB | 4.543 s / 5.79 GiB | 3.188 s / 3.90 GiB | 1.0% / 51.1% | 29.8% / 32.6% |
| 2× Groth16 | 31.920 s / 19.91 GiB | 24.985 s / 14.26 GiB | 18.682 s / 9.00 GiB | 21.7% / 28.4% | 25.2% / 36.9% |
| 2× PLONK | 39.692 s / 18.37 GiB | 35.790 s / 12.63 GiB | 25.936 s / 7.99 GiB | 9.8% / 31.2% | 27.5% / 36.8% |

### Fibonacci 1,000 · 2 core shards

| Mode | Parent time / peak | Round 1 time / peak | Round 2 time / peak | Round 1 reduction, time / RSS | Round 2 reduction, time / RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| Core | 0.596 s / 9.82 GiB | 0.396 s / 3.92 GiB | 0.207 s / 1.54 GiB | 33.6% / 60.1% | 47.8% / 60.6% |
| Compressed | 1.195 s / 10.24 GiB | 0.997 s / 4.32 GiB | 0.686 s / 1.91 GiB | 16.6% / 57.8% | 31.1% / 55.9% |
| 2× Groth16 | 24.364 s / 19.63 GiB | 17.624 s / 13.79 GiB | 12.837 s / 6.80 GiB | 27.7% / 29.8% | 27.2% / 50.7% |
| 2× PLONK | 33.755 s / 17.99 GiB | 28.926 s / 12.34 GiB | 20.632 s / 6.80 GiB | 14.3% / 31.4% | 28.7% / 44.9% |

### First and repeat SNARK proof times

These are medians of the first and second SDK calls for eight-shard SHA-256. Each session used one server and one input. The commit totals above take the median of the two-call sum in each session.

| Mode | Parent, first / repeat | Round 1, first / repeat | Round 2, first / repeat |
| --- | ---: | ---: | ---: |
| 2× Groth16 | 16.653 s / 15.418 s | 15.171 s / 11.837 s | 10.147 s / 9.262 s |
| 2× PLONK | 26.221 s / 19.550 s | 20.705 s / 15.750 s | 14.760 s / 12.719 s |

## Individual changes

For each row, the benchmark switches the named change off and compares it with the corresponding enabled build. The table gives the median of three paired differences, disabled minus enabled. A positive value means seconds or GiB saved by enabling the change. The last column counts the pairs with faster proofs and lower peak RSS respectively. A count of one or two means the direction varied across trials. Bold names mark changes that improved both metrics in all three pairs. This happened in 6 of 97 comparisons across the four modes (2 core, 0 compressed, 2 Groth16 and 2 PLONK).

All rows use eight-shard SHA-256 except the marked two-shard Fibonacci staging comparison. That comparison holds the number of host staging slots at two. A single session includes one core or compressed proof or two consecutive SNARK proofs. The changes share work and affect which stage reaches the memory peak. Use the stock commit comparisons for their total effect.

### Core

In round 1, reusing the RISC-V machine saved 0.194 s. Sharing the stage buffers saved 5.90 GiB at peak. In round 2, admitting independent shards concurrently was 0.40 s faster with peak RSS 0.22 GiB higher on eight shards. The jemalloc changes saved a median 0.057 s and 0.26 GiB. Both improved in all three pairs. Sizing staging buffers to each AIR saved 2.13 GiB on two-shard Fibonacci.

**Round 1 · `03adf8d0c`**

| Change | Proof time saved, s | Peak RSS saved, GiB | Faster / lower, each of 3 |
| --- | ---: | ---: | ---: |
| Share two pinned buffers across all four stages | +0.001 | +5.895 | 2 / 3 |
| **Reuse the local RISC-V machine and consume its request** | +0.194 | +0.033 | 3 / 3 |

**Round 2 · `c98af6e40`**

| Change | Proof time saved, s | Peak RSS saved, GiB | Faster / lower, each of 3 |
| --- | ---: | ---: | ---: |
| Size host trace buffers per AIR, keeping two staging slots (two-shard Fibonacci) | −0.006 | +2.127 | 0 / 3 |
| Admit independent shard proofs concurrently within a workspace budget | +0.400 | −0.220 | 3 / 0 |
| Reuse committed preprocessing for core and eligible recursion shards | −0.014 | −0.094 | 1 / 1 |
| Keep AIR rows generated alongside byte lookup dependencies | −0.067 | −0.180 | 0 / 1 |
| Count SHA-256 byte lookups in dense tables | +0.041 | −0.031 | 3 / 1 |
| Batch LogUp folds, cache fold metadata and finish small sumchecks on CPU | +0.094 | −0.098 | 3 / 1 |
| Fold FRI codewords directly on the GPU | +0.021 | −0.064 | 2 / 1 |
| Compress up to four KoalaBear Merkle layers per GPU launch | +0.059 | −0.133 | 3 / 1 |
| Set Rayon and core worker counts for the host and shard height | +0.287 | +0.009 | 3 / 2 |
| **Limit jemalloc arenas and return dirty pages sooner** | +0.057 | +0.259 | 3 / 3 |
| Reuse the core and recursion verifier objects | +0.070 | +0.053 | 3 / 2 |
| Batch independent NTTs and zero-pad unit cosets in bulk | −0.019 | −0.116 | 1 / 1 |
| Accumulate the GPU byte histogram per block | +0.126 | −0.025 | 2 / 1 |
| Count trusted instructions in an array indexed by program counter | +0.057 | −0.009 | 2 / 1 |
| Batch FRI query verification and reuse checked Merkle ancestors on CPU | +0.011 | −0.097 | 2 / 0 |

### Compressed

Round 1 machine reuse saved 0.181 s. Sharing stage buffers saved 5.71 GiB and made the median proof 0.123 s slower. In round 2, concurrent shard proving was 0.94 s faster with peak RSS 0.23 GiB higher and preprocessing reuse was 0.20 s faster with peak RSS 0.19 GiB higher on eight shards. Retaining generated AIR rows alongside their byte lookups was 0.09 s slower with peak RSS 0.36 GiB higher. Both metrics got worse in all three pairs.

**Round 1 · `03adf8d0c`**

| Change | Proof time saved, s | Peak RSS saved, GiB | Faster / lower, each of 3 |
| --- | ---: | ---: | ---: |
| Share two pinned buffers across all four stages | −0.123 | +5.708 | 1 / 3 |
| Reuse the local RISC-V machine and consume its request | +0.181 | +0.071 | 3 / 2 |

**Round 2 · `c98af6e40`**

| Change | Proof time saved, s | Peak RSS saved, GiB | Faster / lower, each of 3 |
| --- | ---: | ---: | ---: |
| Size host trace buffers per AIR, keeping two staging slots (two-shard Fibonacci) | −0.016 | +2.157 | 0 / 3 |
| Admit independent shard proofs concurrently within a workspace budget | +0.939 | −0.231 | 3 / 1 |
| Reuse committed preprocessing for core and eligible recursion shards | +0.196 | −0.185 | 3 / 0 |
| Keep AIR rows generated alongside byte lookup dependencies | −0.088 | −0.361 | 0 / 0 |
| Count SHA-256 byte lookups in dense tables | +0.070 | −0.115 | 2 / 0 |
| Batch LogUp folds, cache fold metadata and finish small sumchecks on CPU | +0.226 | +0.025 | 2 / 2 |
| Fold FRI codewords directly on the GPU | +0.085 | +0.203 | 2 / 2 |
| Compress up to four KoalaBear Merkle layers per GPU launch | −0.012 | +0.021 | 1 / 2 |
| Set Rayon and core worker counts for the host and shard height | +0.338 | −0.117 | 3 / 0 |
| Limit jemalloc arenas and return dirty pages sooner | −0.053 | +0.308 | 1 / 3 |
| Reuse the core and recursion verifier objects | −0.070 | +0.018 | 0 / 2 |
| Coalesce concurrent normalize compilations for the same shape | +0.009 | −0.202 | 2 / 1 |
| Overlap core verification with recursion execution | +0.024 | −0.207 | 2 / 1 |
| Batch independent NTTs and zero-pad unit cosets in bulk | −0.132 | +0.094 | 1 / 2 |
| Accumulate the GPU byte histogram per block | −0.058 | −0.255 | 0 / 1 |
| Count trusted instructions in an array indexed by program counter | +0.059 | −0.123 | 2 / 1 |
| Batch FRI query verification and reuse checked Merkle ancestors on CPU | −0.015 | +0.068 | 1 / 2 |

### 2× Groth16

Round 1 parallelized the outer proof-of-work search, saving 5.75 s per pair. The outer hash changes saved 0.66 s and 0.17 GiB. In round 2, streaming the proving-key tables was 0.22 s slower with peak RSS 2.99 GiB lower. Loading the gnark circuit and key during STARK proving was 1.77 s faster with peak RSS 1.67 GiB higher. GPU construction of QAP rows saved 0.24 s.

**Round 1 · `03adf8d0c`**

| Change | Proof time saved, s | Peak RSS saved, GiB | Faster / lower, each of 3 |
| --- | ---: | ---: | ---: |
| **Share two pinned buffers across all four stages** | +2.743 | +5.881 | 3 / 3 |
| Reuse the local RISC-V machine and consume its request | +0.726 | −0.042 | 3 / 0 |
| Search for the outer proof-of-work witness across GPU blocks | +5.749 | +0.190 | 3 / 2 |
| **Pack KoalaBear limbs directly and simplify the BN254 Poseidon2 matrix** | +0.662 | +0.173 | 3 / 3 |
| Read large gnark circuit sections in parallel | +0.130 | +0.054 | 2 / 2 |
| Construct the Groth16 witness vector directly | +0.059 | +0.224 | 2 / 3 |
| Copy contiguous Groth16 scalar runs around omitted wires | −0.257 | −0.077 | 0 / 1 |
| Remove host FFT padding from two Groth16 solver arrays | +0.615 | +0.067 | 2 / 2 |

**Round 2 · `c98af6e40`**

| Change | Proof time saved, s | Peak RSS saved, GiB | Faster / lower, each of 3 |
| --- | ---: | ---: | ---: |
| Size host trace buffers per AIR, keeping two staging slots (two-shard Fibonacci) | −0.046 | +2.112 | 1 / 3 |
| Admit independent shard proofs concurrently within a workspace budget | +0.619 | +0.105 | 3 / 2 |
| Reuse committed preprocessing for core and eligible recursion shards | +0.211 | −0.028 | 2 / 1 |
| Keep AIR rows generated alongside byte lookup dependencies | −0.221 | −0.031 | 0 / 1 |
| Count SHA-256 byte lookups in dense tables | +0.164 | +0.136 | 2 / 2 |
| Batch LogUp folds, cache fold metadata and finish small sumchecks on CPU | +0.247 | +0.140 | 2 / 2 |
| Fold FRI codewords directly on the GPU | −0.317 | −0.030 | 1 / 1 |
| Compress up to four KoalaBear Merkle layers per GPU launch | +0.077 | +0.099 | 2 / 2 |
| Set Rayon and core worker counts for the host and shard height | +0.435 | −0.325 | 3 / 0 |
| Limit jemalloc arenas and return dirty pages sooner | −0.124 | +0.078 | 1 / 2 |
| Reuse the core and recursion verifier objects | +0.610 | +0.003 | 3 / 2 |
| Coalesce concurrent normalize compilations for the same shape | −0.212 | +0.005 | 1 / 2 |
| Overlap core verification with recursion execution | −0.111 | +0.021 | 1 / 2 |
| Reuse ELF setup across SDK requests | −0.074 | +0.037 | 0 / 2 |
| Start preparing the wrap prover during core proving | +0.540 | −0.613 | 3 / 0 |
| Load the gnark circuit and key during STARK proving | +1.770 | −1.674 | 3 / 0 |
| Stream Groth16 proving-key point tables through bounded buffers | −0.219 | +2.987 | 1 / 3 |
| Build the Groth16 QAP rows on the GPU | +0.237 | +0.005 | 3 / 2 |
| Batch independent NTTs and zero-pad unit cosets in bulk | −0.498 | −0.234 | 1 / 0 |
| Accumulate the GPU byte histogram per block | −0.110 | −0.201 | 1 / 0 |
| Count trusted instructions in an array indexed by program counter | +0.231 | −0.022 | 2 / 1 |
| Batch FRI query verification and reuse checked Merkle ancestors on CPU | +0.937 | −0.424 | 3 / 0 |

### 2× PLONK

Round 1 parallelized the outer proof-of-work search, saving 3.54 s per pair. Shared stage buffers saved 5.94 GiB at peak. Round 2 kept the quotient and its coset caches on the GPU, saving 1.74 s and 2.58 GiB. Loading gnark during STARK proving was 1.71 s faster with peak RSS 0.34 GiB higher.

**Round 1 · `03adf8d0c`**

| Change | Proof time saved, s | Peak RSS saved, GiB | Faster / lower, each of 3 |
| --- | ---: | ---: | ---: |
| Share two pinned buffers across all four stages | −0.757 | +5.936 | 1 / 3 |
| Reuse the local RISC-V machine and consume its request | +0.075 | +0.092 | 2 / 2 |
| Search for the outer proof-of-work witness across GPU blocks | +3.541 | −0.308 | 2 / 1 |
| Pack KoalaBear limbs directly and simplify the BN254 Poseidon2 matrix | +0.794 | −0.094 | 3 / 1 |
| Read large gnark circuit sections in parallel | −0.141 | +0.199 | 1 / 2 |
| Reuse PLONK’s permutation polynomial across the first three cosets | −0.253 | +0.089 | 1 / 2 |

**Round 2 · `c98af6e40`**

| Change | Proof time saved, s | Peak RSS saved, GiB | Faster / lower, each of 3 |
| --- | ---: | ---: | ---: |
| Size host trace buffers per AIR, keeping two staging slots (two-shard Fibonacci) | −0.032 | +2.150 | 1 / 3 |
| Admit independent shard proofs concurrently within a workspace budget | +1.418 | −0.167 | 3 / 0 |
| Reuse committed preprocessing for core and eligible recursion shards | +0.683 | −0.578 | 3 / 0 |
| Keep AIR rows generated alongside byte lookup dependencies | −0.022 | −0.733 | 1 / 1 |
| Count SHA-256 byte lookups in dense tables | +0.424 | −0.063 | 3 / 1 |
| Batch LogUp folds, cache fold metadata and finish small sumchecks on CPU | +0.560 | −0.199 | 3 / 1 |
| Fold FRI codewords directly on the GPU | +0.029 | −0.002 | 2 / 1 |
| Compress up to four KoalaBear Merkle layers per GPU launch | −0.188 | −0.056 | 1 / 1 |
| Set Rayon and core worker counts for the host and shard height | +0.201 | −0.508 | 2 / 0 |
| **Limit jemalloc arenas and return dirty pages sooner** | +0.628 | +0.356 | 3 / 3 |
| Reuse the core and recursion verifier objects | −0.018 | −0.427 | 1 / 0 |
| Coalesce concurrent normalize compilations for the same shape | +0.267 | +0.324 | 2 / 3 |
| Overlap core verification with recursion execution | +0.052 | −0.318 | 2 / 0 |
| Reuse ELF setup across SDK requests | −0.096 | −0.088 | 1 / 1 |
| Start preparing the wrap prover during core proving | +0.355 | −0.409 | 3 / 0 |
| Load the gnark circuit and key during STARK proving | +1.710 | −0.342 | 3 / 0 |
| **Keep the PLONK quotient on device with its dependent coset caches** | +1.741 | +2.584 | 3 / 3 |
| Reuse canonical PLONK coefficients across quotient cosets | −0.018 | +0.008 | 1 / 2 |
| Evaluate six PLONK openings in one barycentric GPU pass | +0.235 | +0.121 | 3 / 2 |
| Combine the transforms for PLONK linearization and batch opening | +0.135 | −0.078 | 2 / 1 |
| Reuse inverses of constant gate coefficients in the PLONK solver | +0.128 | +0.023 | 2 / 2 |
| Batch independent NTTs and zero-pad unit cosets in bulk | +0.164 | −0.307 | 2 / 1 |
| Accumulate the GPU byte histogram per block | +0.394 | +0.006 | 3 / 2 |
| Count trusted instructions in an array indexed by program counter | +0.254 | −0.298 | 3 / 0 |
| Batch FRI query verification and reuse checked Merkle ancestors on CPU | +1.271 | −0.082 | 3 / 1 |

## Capacity at the default shard limit

The larger default-height guests exercised a different limit. The round-one server exhausted CUDA memory on both 2 MiB SHA-256 (six core shards) and four-million-iteration Fibonacci (eight core shards) in all four modes. The round-two server verified all four modes on both guests. Its highest observed combined host RSS was **12.16 GiB**, for two PLONK proofs of the larger Fibonacci input.

Releasing the encoded main trace before a large LogUp proof and re-encoding it for FRI made a measurable difference to completion. An intermediate build that retained the trace verified the first PLONK proof on the larger Fibonacci guest in 21.10 s, then exhausted CUDA memory during the repeat. The final configuration completed three two-proof sessions, with a median total of 40.26 s. The failed repeat established a capacity difference under the original device load. [Default-height benchmark results](sdk-proof-benchmarks.md)

After other applications were closed, all eight original round-one failures verified, and the intermediate server completed both proofs on the same eight-shard Fibonacci input. Peak host RSS on round two ranged from 5.20 to 12.06 GiB across these matched runs. Round two was slower in the core and compressed Fibonacci runs. [Retry conditions, times and simultaneous SDK-plus-server RSS](sdk-proof-benchmarks.md#retried-with-more-device-memory-on-25-november)

## Measurement and attribution

- **Workloads.** SHA-256 hashed 1 MiB of zeros. Fibonacci ran 1,000,000 iterations. Both used a height threshold of 262,144. Every stock core proof confirmed eight and nine shards respectively. The small stock-commit comparison and two-slot staging comparison used 1,000 Fibonacci iterations at the default height threshold of 4,194,304, producing two shards.
- **Proof time.** A single release CUDA SDK client launched the installed GPU server afresh for each session. A monotonic timer bracketed each SDK proof call. The client independently verified each result after stopping that timer. SDK setup preceded the timed calls. Groth16 and PLONK each proved the same input twice on one server, so each pair contains a first proof and a proof with the key cache warm.
- **Peak RSS.** The sampler followed the SDK client and its actual `~/.sp1/bin/sp1-gpu-server` child, read both resident sets together from `/proc/<pid>/statm` and slept 4 ms between samples. The maximum covers startup, setup, proving, verification and shutdown. Each process contributes its own resident pages, including shared mappings. Separate GPU telemetry records free device memory at session start.
- **Hardware and controls.** One NVIDIA GeForce RTX 4090 with 24,564 MiB of device memory and one 16-core, 32-thread AMD Ryzen 9 5950X ran the sessions serially. Switch order was randomized within each mode and repetition. The same client and guest ELF were used for every commit. Each release server variant was installed before use. Every change was compared with an enabled control in its own comparison block.
- **Shared trace buffers.** The worker builder sets the pinned allocation from the four stage capacities. The first-round parent allocated four buffers at each stage’s capacity, reserving 8.05 GiB in total. Round one shared two buffers of the largest stage’s capacity, reserving 2.14 GiB. The 5.91 GiB difference describes the allocation. The RSS rows measure the resulting change at each session’s actual peak.
- **Grouped changes.** The worker-count row includes the Rayon thread limit and the number of CPU core-proving workers. The LogUp row includes batched folds, cached fold metadata and the CPU tail for small sumchecks. The PLONK quotient-storage row includes dependent coset caches. The separate quotient-cache row holds device storage enabled and varies reuse of canonical coefficients. The CPU opening-verification row includes FRI query arithmetic and reuse of checked Merkle ancestors.
- **Correctness fixes.** Both sides of the grinding comparison keep the corrected atomic winner selection. Both sides of the NTT comparison keep the synchronization fix. The earlier study also checked CPU/GPU transforms under NVIDIA Compute Sanitizer and verified 12 additional eight-shard compressed proofs under higher concurrency. [Validation and stress results](sdk-proof-benchmarks.md)

## Background load and repeatability

The host ran other work during the study. The benchmark repeated a whole block if its telemetry crossed between low and busy CPU/GPU conditions, or if GPU utilization at launch ranged from at most 40% to at least 70% within the block. This affected 3 blocks and 14 selected sessions. The raw archive retains every original and replacement. For smaller effects, the counts and ranges show how often the direction varied. The individual changes interact, so their savings cannot be added to predict commit totals.

A closing calibration repeated the eight-shard SHA-256 stock round-two build three more times per mode. Median external CPU use was 3.6 logical cores in its original sessions and 3.9 in the closing sessions. Median GPU utilization at launch was 20% and 20% respectively.

| Mode | Original time / peak | Closing time / peak |
| --- | ---: | ---: |
| Core | 2.319 s / 3.97 GiB | 2.304 s / 3.83 GiB |
| Compressed | 3.772 s / 4.26 GiB | 3.771 s / 4.19 GiB |
| 2× Groth16 | 19.376 s / 8.64 GiB | 19.855 s / 8.43 GiB |
| 2× PLONK | 27.465 s / 8.06 GiB | 28.065 s / 7.91 GiB |

Separate main-branch builds measure the changes submitted for review on a 102-shard Ethereum block. [RSP timings for the individual PRs](sdk-rsp-pr-benchmarks.md)
