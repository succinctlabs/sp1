# Ethereum RSP proof benchmarks

## Guest and measurement

The checked-in RSP guest re-executed Ethereum mainnet block 21,740,136, with 88 transactions and 5,524,782 gas. The core proof had 102 shards at `HEIGHT_THRESHOLD=262144`. Main produced 36 core shards for the same block at the default height. Each proof returned the expected 748-byte header. Its Keccak-256 hash was `0xd42ec18b0b56fed31aa3976057fae903251f7d409651335780ead557502d0413`. [Ethereum block](https://eth.blockscout.com/block/21740136)

Runs used one RTX 4090 and a Ryzen 9 5950X. The same release SDK client launched each matching release server from `~/.sp1/bin` and independently verified the proof. Time covers the SDK proof call. Host RSS is the largest simultaneous sum for the client and server, sampled with a 4 ms sleep from startup through shutdown.

The SDK set up the checked-in ELF, passed the block file bytes in one `SP1Stdin::write_vec` call, then timed `client.prove(&pk, stdin.clone()).mode(mode).await`. Setup preceded the timer and each returned proof was verified after it. The ELF SHA-256 was `6077a757923815224135f8b6d7e312ceebe3dc4ce5fef57a9619a65a81ff2dd1` and the input SHA-256 was `b52377988c8cf68246234790c7c4cde97d670fa94d86d5f65e8501998d458e25`. [Guest ELF](../crates/perf/programs/rsp/elf/rsp-client) · [Block input](../crates/perf/programs/rsp/input/21740136.bin)

To install the matching CUDA server from a checkout on Linux, run the following from the workspace root. The RSP comparisons used `HEIGHT_THRESHOLD=262144` unless the table specifies the default height.

```sh
SP1_CUDA_ENABLED=true cargo build --release --locked -p sp1-gpu-server
install -D -m 755 target/release/sp1-gpu-server ~/.sp1/bin/sp1-gpu-server
```

Rows below report the median per-session SDK proof time and the largest observed peak RSS. Groth16 and PLONK use two successive proofs of the identical input on one fresh server. Installed CUDA servers were rebuilt from the listed revisions. SDK verification followed each proof.

## Independent pull requests against main

Each comparison pairs the PR with main at `0cd151a8d` on the same workload. The core shard-height limit was 262,144. The initial pre-retry main pilot is excluded. Main used the GPU for STARK proving and CPU gnark for the final wrap. Native PLONK used `GOMEMLIMIT=23GiB GOGC=30 GOMAXPROCS=16` on both sides.

| PR and change | Mode | Paired sessions | Main time | PR time | Time change | Main peak RSS | PR peak RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| [#3046](https://github.com/succinctlabs/sp1/pull/3046) RISC-V machine reuse | Core | 2 | 20.256 s | 20.362 s | +0.5% | 13.18 GiB | 13.12 GiB |
| [#3046](https://github.com/succinctlabs/sp1/pull/3046) RISC-V machine reuse | Compressed | 2 | 39.452 s | 39.117 s | -0.8% | 14.34 GiB | 13.81 GiB |
| [#3047](https://github.com/succinctlabs/sp1/pull/3047) Borrowed host copies | Core | 2 | 20.007 s | 20.370 s | +1.8% | 13.17 GiB | 13.27 GiB |
| [#3047](https://github.com/succinctlabs/sp1/pull/3047) Borrowed host copies | Compressed | 2 | 39.058 s | 39.649 s | +1.5% | 13.83 GiB | 13.75 GiB |
| [#3048](https://github.com/succinctlabs/sp1/pull/3048) SPPARK NTT synchronization | Core | 2 | 20.007 s | 20.293 s | +1.4% | 13.17 GiB | 13.19 GiB |
| [#3048](https://github.com/succinctlabs/sp1/pull/3048) SPPARK NTT synchronization | Compressed | 2 | 39.058 s | 39.144 s | +0.2% | 13.83 GiB | 13.85 GiB |
| [#3049](https://github.com/succinctlabs/sp1/pull/3049) STARK grinding | 2× Groth16 | 2 | 154.924 s | 139.196 s | -10.2% | 35.23 GiB | 35.32 GiB |
| [#3049](https://github.com/succinctlabs/sp1/pull/3049) STARK grinding | 2× PLONK | 2 | 655.019 s | 646.843 s | -1.2% | 45.74 GiB | 45.77 GiB |
| [#3050](https://github.com/succinctlabs/sp1/pull/3050) Outer Poseidon2 | 2× Groth16 | 2 | 154.924 s | 140.434 s | -9.4% | 35.23 GiB | 35.47 GiB |
| [#3050](https://github.com/succinctlabs/sp1/pull/3050) Outer Poseidon2 | 2× PLONK | 2 | 655.019 s | 651.098 s | -0.6% | 45.74 GiB | 46.25 GiB |
| [#3051](https://github.com/succinctlabs/sp1/pull/3051) Shared recursive trace buffers | Core | 5 | 20.168 s | 20.143 s | -0.1% | 13.15 GiB | 11.39 GiB |
| [#3051](https://github.com/succinctlabs/sp1/pull/3051) Shared recursive trace buffers | Compressed | 3 | 39.256 s | 39.115 s | -0.4% | 14.35 GiB | 12.09 GiB |
| [#3052](https://github.com/succinctlabs/sp1/pull/3052) LogUp device-memory budget | Core | 2 | 20.169 s | 20.083 s | -0.4% | 13.25 GiB | 13.09 GiB |
| [#3052](https://github.com/succinctlabs/sp1/pull/3052) LogUp device-memory budget | Compressed | 2 | 39.102 s | 39.562 s | +1.2% | 14.02 GiB | 13.87 GiB |
| [#3054](https://github.com/succinctlabs/sp1/pull/3054) Release idle allocator pages | Core | 3 | 21.072 s | 20.775 s | -1.4% | 12.68 GiB | 12.13 GiB |
| [#3054](https://github.com/succinctlabs/sp1/pull/3054) Release idle allocator pages | Compressed | 3 | 39.465 s | 39.300 s | -0.4% | 13.70 GiB | 12.89 GiB |
| [#3055](https://github.com/succinctlabs/sp1/pull/3055) Return the initial digest for empty global traces | Core | 1 | 36.841 s | 66.535 s | +80.6% | 12.59 GiB | 12.53 GiB |
| [#3055](https://github.com/succinctlabs/sp1/pull/3055) Return the initial digest for empty global traces | Compressed | 1 | 84.215 s | 66.254 s | -21.3% | 13.35 GiB | 13.29 GiB |

## SHA-256 control for RISC-V machine reuse

The initial three-session SHA-256 core comparison suggested a 34.2% reduction. Across ten alternating pairs on the same eight-shard input, core fell from 2.770 to 2.557 s (7.7%) and compressed from 4.670 to 4.415 s (5.5%). The PR was faster in all twenty pairs. Constructing the RISC-V machine took 237 ms per request. Cloning the configured machine took 0.019 ms. The original baseline varied from 6.784 to 14.963 s, and the multi-second difference did not reproduce. [All forty proofs and the construction benchmark](https://github.com/succinctlabs/sp1/pull/3046)

## The two combined CUDA prover rounds

The original CUDA wrapper at `6f14261e8`, round one at `03adf8d0c`, and round two at `c98af6e40` all used the GPU for gnark. Round one and round two ran consecutively on the same 102-shard block, once per build and mode. Each wrapping session verified two proofs with Go defaults. Both the original CUDA PR core and compressed figures use one fresh session. The original CUDA PR wrapping figures come from the three earlier sessions per mode in the outer STARK comparison below. The last row sums elapsed time over one core proof, one compressed proof and two proofs of each wrapping mode, and gives the largest RSS across the four sessions. The direct final-prover comparisons use fresh, separately paired controls.

| Mode | CUDA PR baseline time / peak | Round 1 time / peak | Round 2 time / peak | Time saved in round 2 | Peak RSS saved in round 2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Core | 22.203 s / 12.61 GiB | 20.868 s / 6.74 GiB | 18.462 s / 5.37 GiB | 11.5% | 20.4% |
| Compressed | 39.214 s / 13.77 GiB | 39.725 s / 7.84 GiB | 29.001 s / 5.47 GiB | 27.0% | 30.2% |
| 2× Groth16 | 98.198 s / 21.19 GiB | 96.987 s / 14.90 GiB | 67.418 s / 8.55 GiB | 30.5% | 42.6% |
| 2× PLONK | 107.547 s / 20.69 GiB | 104.530 s / 14.54 GiB | 75.506 s / 9.55 GiB | 27.8% | 34.3% |
| All four modes | — | 262.110 s / 14.90 GiB | 190.387 s / 9.55 GiB | 27.4% | 35.9% |

### Where time went in the 102-shard core proof

A separate instrumented round-two core proof verified the same block header in 25.995 s. CUPTI recorded 159,919 kernels and 152,172 copies. Their non-overlapping wall-clock coverage was 14.694 s, leaving 11.301 s outside recorded device work. Host-to-device transfers totaled 23.40 GiB and device-to-host transfers totaled 0.20 GiB. At least one host thread was inside a stream or device synchronization call for 6.757 s. These intervals can overlap device work.

A simultaneous 14-second server CPU sample attributed 3.92 CPU-seconds to the tracing VM execution loop, 3.23 to base-field inversion and 2.58 to merging byte lookup counts. These are sampled times summed over threads. The uninstrumented runs in the preceding table provide the proof-time comparison.

A second instrumented core proof verified the same block header in 24.163 s. CUDA call stacks identified 52,899 device-to-host calls across 23 sites. Of these calls, 46,100 copied 4 KiB or less. The four sites below had the longest elapsed waits. A synchronous copy can include the wait for earlier kernels in the stream, and different sites can overlap.

| GPU result copied to the host | Calls | Elapsed time with a caller waiting | Wait time summed across threads |
| --- | ---: | ---: | ---: |
| Merkle tree root | 2,244 | 4.575 s | 5.361 s |
| LogUp round sums | 23,718 | 2.544 s | 3.414 s |
| Jagged assist round polynomial | 5,718 | 1.885 s | 2.336 s |
| Global interaction digest | 1,428 | 1.076 s | 11.708 s |

The global interaction digest used fourteen four-byte copies per shard. On 102 shards these transferred 5,712 bytes in total.

A separate pair on main verified the same RSP block and counted 1,428 four-byte digest copies on the control and 102 contiguous 56-byte copies with the change. The uninstrumented end-to-end measurements used separate sessions.

## Additional independent candidates measured locally

Build order rotated within each comparison. The first table identifies the revisions submitted for review.

| Local main-branch candidate | Mode | Sessions per build | Main proof time | Candidate proof time | Main peak RSS | Candidate peak RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Move local artifact bytes and share typed download snapshots | Core | 3 | 21.072 s | 21.054 s | 12.68 GiB | 12.71 GiB |
| Move local artifact bytes and share typed download snapshots | Compressed | 3 | 39.465 s | 39.425 s | 13.70 GiB | 13.60 GiB |
| Serialize owned and spliced trace data in bulk | Core | 3 | 21.072 s | 21.954 s | 12.68 GiB | 12.60 GiB |
| Serialize owned and spliced trace data in bulk | Compressed | 3 | 39.465 s | 39.837 s | 13.70 GiB | 13.40 GiB |
| Generate integer multiplication rows without temporary vectors | Core | 3 | 21.702 s | 22.466 s | 12.72 GiB | 12.69 GiB |
| Generate integer multiplication rows without temporary vectors | Compressed | 3 | 40.141 s | 40.152 s | 13.63 GiB | 13.75 GiB |
| Move uploaded artifact bytes into the existing map | Core | 2 | 21.355 s | 21.438 s | 12.63 GiB | 12.65 GiB |
| Move uploaded artifact bytes into the existing map | Compressed | 2 | 39.486 s | 39.627 s | 13.78 GiB | 13.63 GiB |
| Borrow memory reads when serializing a trace | Core | 2 | 21.355 s | 21.270 s | 12.63 GiB | 12.63 GiB |
| Borrow memory reads when serializing a trace | Compressed | 2 | 39.486 s | 39.626 s | 13.78 GiB | 13.65 GiB |
| Encode and decode the core trace byte vector in bulk | Core | 2 | 21.355 s | 21.013 s | 12.63 GiB | 12.81 GiB |
| Encode and decode the core trace byte vector in bulk | Compressed | 2 | 39.486 s | 39.303 s | 13.78 GiB | 13.41 GiB |
| Skip discarded byte lookup vectors while writing CPU trace rows | Core | 3 | 21.702 s | 21.566 s | 12.72 GiB | 12.66 GiB |
| Skip discarded byte lookup vectors while writing CPU trace rows | Compressed | 3 | 40.141 s | 40.925 s | 13.63 GiB | 13.45 GiB |
| Reuse high address limb inverses on each CPU trace worker | Core | 3 | 26.430 s | 26.800 s | 13.06 GiB | 13.06 GiB |
| Reuse high address limb inverses on each CPU trace worker | Compressed | 3 | 52.908 s | 52.738 s | 13.91 GiB | 13.60 GiB |
| Expand multiplication rows from their operands on the device | Core | 3 | 31.033 s | 27.412 s | 12.73 GiB | 12.68 GiB |
| Expand multiplication rows from their operands on the device | Compressed | 3 | 42.862 s | 42.724 s | 13.56 GiB | 13.39 GiB |
| Copy each global interaction digest in a single transfer | Core | 5 | 25.893 s | 26.590 s | 12.83 GiB | 12.77 GiB |
| Copy each global interaction digest in a single transfer | Compressed | 5 | 53.662 s | 53.659 s | 13.68 GiB | 13.51 GiB |

On main the CPU generates multiplication rows on demand. The port that expands them on the GPU finished faster in 2/3 core and 1/3 compressed RSP pairs.

During the RSP sessions, NVIDIA process telemetry sampled other applications every two seconds while the proving server was visible on the GPU. Summed streaming-multiprocessor utilization for those applications averaged 0–17% per session on the control and 0–20% on the changed build.

### CPU multiplication and lookup generation

Each of nine alternating release-process pairs populated 250,000 multiplication rows with identical checksums. Removing the temporary vectors reduced the median per trace row from 240.0 to 157.2 ns and per dependency row from 456.0 to 390.1 ns. Core RSP proof time increased in all three end-to-end pairs.

A second change skipped byte lookups that the CPU trace writer immediately discarded. Five release-process pairs replayed each captured shard using 16 Rayon threads. Both builds produced the same digest of every field element and sorted byte-lookup multiplicity for every affected AIR present. The table gives median time to generate the trace matrices. The installed-server RSP compressed proof took longer in each of its three pairs.

| Captured record | AIRs | Matched trace cells | Main | Skip discarded lookups |
| --- | ---: | ---: | ---: | ---: |
| RSP | 12 | 49,236,288 | 30.4 ms | 29.1 ms |
| Four-million-iteration Fibonacci | 7 | 282,934,016 | 150.7 ms | 139.1 ms |

### Address inversions in captured RSP execution records

Four captured records contained 2,146,367 load and store events. Their upper address limbs produced 9 to 82 distinct sums per record. Replaying field inversion in isolation with a 16-entry direct-mapped cache per worker reduced the sum of the four single-thread medians from 186.7 to 6.2 ms. Each record had three repetitions with matching checksums. The end-to-end comparisons use complete verified RSP proofs.

## LogUp on two RSP shard sizes

Two additional rotated pairs measured compressed time and host RSS at each shard height. A separate debug run on the same release binary counted the main-codeword releases during FRI. [LogUp device-memory PR](https://github.com/succinctlabs/sp1/pull/3052)

| RSP core shards | Main compressed time | PR compressed time | Main peak RSS | PR peak RSS | Codewords released in separate PR run |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 102 | 39.358 s | 39.393 s | 14.33 GiB | 14.03 GiB | 0 |
| 36 | 22.907 s | 22.652 s | 16.16 GiB | 16.24 GiB | 0 |

## Multiplication trace generation on the GPU

The control uses the revised LogUp budget on the round-two branch. The candidate expands each multiplication operation from its operands on the device. A separate release test compared every trace cell to the CPU across all five opcodes and both trust modes. NVIDIA Compute Sanitizer memcheck reported zero errors.

| Change | Mode | Sessions per build | Baseline proof time | Changed proof time | Baseline peak RSS | Changed peak RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Multiplication trace on device | Core | 3 | 26.207 s | 26.242 s | 5.40 GiB | 5.72 GiB |
| Multiplication trace on device | Compressed | 3 | 40.714 s | 40.219 s | 5.66 GiB | 5.80 GiB |

## Revised host and device admission on RSP

Two rotations compared the original rounds with CUDA build `510c8ad0a`. Each cell gives median time and the largest simultaneous client-plus-server host RSS. [All six guests](sdk-proof-benchmarks.md#selected-cuda-follow-up)

| Mode | Round one | Round two | Follow-up | Time saved vs. round one | Peak RSS saved vs. round one |
| --- | ---: | ---: | ---: | ---: | ---: |
| Core | 24.796 s / 6.72 GiB | 22.097 s / 5.51 GiB | 20.438 s / 5.53 GiB | 17.6% | 17.8% |
| Compressed | 51.349 s / 7.81 GiB | 36.835 s / 6.27 GiB | 33.143 s / 5.41 GiB | 35.5% | 30.7% |
| 2× Groth16 | 124.513 s / 14.78 GiB | 85.062 s / 8.66 GiB | 80.280 s / 8.35 GiB | 35.5% | 43.5% |
| 2× PLONK | 132.691 s / 14.46 GiB | 91.766 s / 9.94 GiB | 86.091 s / 9.68 GiB | 35.1% | 33.1% |

### Multiplication after host trace admission

Both CUDA releases generated CPU trace rows after host admission. Three alternating pairs per mode compared CPU and GPU expansion of multiplication events on the same RSP block.

| Change | Mode | Sessions per build | Baseline proof time | Changed proof time | Baseline peak RSS | Changed peak RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Multiplication trace on device | Core | 3 | 22.650 s | 23.016 s | 5.61 GiB | 5.57 GiB |
| Multiplication trace on device | Compressed | 3 | 37.604 s | 37.572 s | 5.33 GiB | 5.78 GiB |

### Allocator arenas after host trace admission

The same CUDA release ran with eight arenas by default and four through the jemalloc environment setting. Each setting used three fresh servers per mode and the same page-decay intervals.

| Change | Mode | Sessions per build | Baseline proof time | Changed proof time | Baseline peak RSS | Changed peak RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Four jemalloc arenas | Core | 3 | 19.979 s | 20.880 s | 5.45 GiB | 5.49 GiB |

The round-one core control ran in the same rotation and measured 26.959 s / 6.67 GiB. [Individual allocator comparisons](sdk-proof-benchmarks.md#allocator-arenas-after-host-trace-admission)

### Rayon thread count after host trace admission

Three alternating pairs used the installed follow-up server. The control server selected 16 threads on this CPU. The alternative launched the SDK and server with `RAYON_NUM_THREADS=12`.

| Change | Mode | Sessions per build | Baseline proof time | Changed proof time | Baseline peak RSS | Changed peak RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Twelve Rayon threads | Core | 3 | 20.855 s | 21.263 s | 5.58 GiB | 5.63 GiB |

### Core prover workers at the smaller shard height

Four rotations compared both original servers with the follow-up using either five or four CPU core-proving workers. Every build proved 102 core shards. Both follow-up settings used four trace staging slots, 24 permits for device workspace and the same installed server binary.

| Server or core-worker setting | Median core proof time | Maximum host RSS |
| --- | ---: | ---: |
| Round one | 26.466 s | 6.60 GiB |
| Round two | 23.109 s | 5.64 GiB |
| Follow-up, five workers | 21.642 s | 5.69 GiB |
| Follow-up, four workers | 22.619 s | 5.16 GiB |

### RSP core across all matched default settings

Each row includes every rotation that ran the control and the follow-up at their default settings on this block. The table gives median proof times and the largest simultaneous SDK and server RSS across the matched sessions. All returned the same block header.

| Control | Matched pairs | Control, time / peak RSS | Follow-up, time / peak RSS | Time saved | Peak RSS saved |
| --- | ---: | ---: | ---: | ---: | ---: |
| Round one | 9 | 26.591 s / 6.72 GiB | 20.541 s / 5.69 GiB | 22.8% | 15.4% |
| Round two | 9 | 22.707 s / 5.64 GiB | 21.057 s / 5.69 GiB | 7.3% | -0.8% |

## CUDA wrapping with additional main-branch changes

Each build applies one independent main-branch change to the original CUDA wrapping revision. Each session used the default Go runtime and verified two full RSP proofs.

| Change | Mode | Sessions per build | Baseline proof time | Changed proof time | Baseline peak RSS | Changed peak RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| [#3054](https://github.com/succinctlabs/sp1/pull/3054) Release idle allocator pages | 2× Groth16 | 3 | 143.018 s | 141.454 s | 20.62 GiB | 19.80 GiB |
| [#3054](https://github.com/succinctlabs/sp1/pull/3054) Release idle allocator pages | 2× PLONK | 3 | 155.921 s | 163.010 s | 20.31 GiB | 19.21 GiB |

## CUDA wrapping with the two outer STARK changes

The baseline for this table is the CUDA wrapper at `6f14261e8`. Each changed build applies one main-branch PR. Both the STARK and the final prover used the GPU, with the default Go runtime. Each session verified two RSP proofs.

| Change | Mode | Sessions per build | Baseline proof time | Changed proof time | Baseline peak RSS | Changed peak RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| [#3049](https://github.com/succinctlabs/sp1/pull/3049) grinding | 2× Groth16 | 3 | 98.198 s | 92.321 s | 21.19 GiB | 20.94 GiB |
| [#3049](https://github.com/succinctlabs/sp1/pull/3049) grinding | 2× PLONK | 3 | 107.547 s | 99.943 s | 20.69 GiB | 20.93 GiB |
| [#3050](https://github.com/succinctlabs/sp1/pull/3050) Poseidon2 | 2× Groth16 | 3 | 98.198 s | 100.280 s | 21.19 GiB | 21.12 GiB |
| [#3050](https://github.com/succinctlabs/sp1/pull/3050) Poseidon2 | 2× PLONK | 3 | 107.547 s | 102.152 s | 20.69 GiB | 20.50 GiB |

## Direct changes to the CUDA final provers

Each comparison starts from the original CUDA wrapper at `6f14261e8`. Each session verified two RSP proofs.

| Change | Mode | Sessions per build | Baseline proof time | Changed proof time | Baseline peak RSS | Changed peak RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| [#3017](https://github.com/succinctlabs/sp1/pull/3017) direct Groth16 | 2× Groth16 | 2 | 144.548 s | 136.863 s | 20.91 GiB | 15.85 GiB |
| [#3017](https://github.com/succinctlabs/sp1/pull/3017) direct PLONK | 2× PLONK | 4 | 146.618 s | 148.196 s | 20.51 GiB | 17.67 GiB |
| Three Groth16 commits in isolation | 2× Groth16 | 3 | 134.179 s | 132.801 s | 21.04 GiB | 16.52 GiB |

The independently built Groth16-only version ran three alternating pairs and was faster in 1/3. The maxima were 21.04 GiB on the original release and 16.52 GiB with the changes.

#### Final-prover control with parallel STARK grinding

For the two guest and mode combinations with slower SDK medians in the original CUDA final-prover comparison, both servers also ran the winner-selection and parallel grinding changes from #3049 at `505caa944`. The control was `9c671ea3b` and the direct final-prover build was `793c98bc6`. Their STARK sources were identical. Each fresh session verified two complete SDK proofs. Build order alternated within pairs.

| Guest | Mode | Pairs | Grinding only | Grinding and final-prover changes | Grinding only peak | With final-prover changes peak | Faster pairs | Median paired time change |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Fibonacci 1,000 (2 shards) | 2× Groth16 | 3 | 18.357 s | 17.642 s | 19.52 GiB | 15.10 GiB | 3/3 | -4.5% |
| Ethereum RSP (102 shards) | 2× PLONK | 2 | 130.241 s | 128.082 s | 20.47 GiB | 17.32 GiB | 1/2 | -1.6% |

During the RSP sessions, NVIDIA process telemetry sampled other applications every two seconds while the proving server was visible on the GPU. Summed streaming-multiprocessor utilization for those applications averaged 19–22% per session on the control and 20% on the changed build.

A separate observer sampled each final-witness file every 25 ms, from serialization through gnark verification. The remaining SDK time is the two-proof total less both file lifetimes. The table uses paired sessions with both intervals observed on each build.

| Guest | Mode | Observed pairs | Control final stage | Changed final stage | Control remaining SDK time | Changed remaining SDK time |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Fibonacci 1,000 (2 shards) | 2× Groth16 | 3 | 10.36 s | 9.75 s | 7.80 s | 7.79 s |
| Ethereum RSP (102 shards) | 2× PLONK | 2 | 21.95 s | 19.73 s | 108.29 s | 108.36 s |

#### Final prover replay on the RSP witness

The SDK produced this final witness while proving Ethereum block 21,740,136. Its committed-values field matched the masked SHA-256 of the 748-byte block header. All builds replayed the exact same witness (SHA-256 `17dd5c330aaba698825a607c04cd357305133b4dafedaed3e390c80730c4bffe`) and installed v6.1.0 circuit files. Each fresh process produced two proofs and independently verified both against the five RSP public inputs.

| Final prover | Build | Median two-proof total | Maximum process RSS |
| --- | --- | ---: | ---: |
| Groth16 | Original CUDA PR | 9.515 s | 9.14 GiB |
| Groth16 | Streamed Groth16 key | 9.269 s | 4.75 GiB |
| Groth16 | Streamed key with parallel reads | 8.621 s | 4.64 GiB |
| PLONK | Original CUDA PR | 20.663 s | 7.93 GiB |
| PLONK | Direct PLONK changes | 18.518 s | 5.28 GiB |

These timings isolate the final provers. The SDK tables above include producing the RSP STARK proof, recursively compressing it and wrapping it.

## Shared trace buffers in both CUDA wrapping modes

Two alternating RSP pairs added the selected main-branch trace-buffer change to the original CUDA wrapper. The four proving stages shared the same trace-buffer policy as the public PR.

| Change | Mode | Sessions per build | Baseline proof time | Changed proof time | Baseline peak RSS | Changed peak RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| [#3051](https://github.com/succinctlabs/sp1/pull/3051) trace buffers | 2× Groth16 | 2 | 100.426 s | 96.854 s | 20.97 GiB | 19.56 GiB |
| [#3051](https://github.com/succinctlabs/sp1/pull/3051) trace buffers | 2× PLONK | 2 | 106.380 s | 104.198 s | 20.77 GiB | 19.06 GiB |

## Additional CUDA PLONK comparisons

Two additional pairs measured the peak host memory of the grinding change. The PR description reports the five-pair total with the three earlier pairs.

| Change | Mode | Sessions per build | Baseline proof time | Changed proof time | Baseline peak RSS | Changed peak RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| [#3049](https://github.com/succinctlabs/sp1/pull/3049) grinding | 2× PLONK | 2 | 113.606 s | 100.745 s | 20.70 GiB | 20.76 GiB |

## Poseidon2 with parallel grinding

Both builds here include the parallel outer proof-of-work search. The changed build adds the outer Poseidon2 PR. Each SDK session verified two proofs.

| Change | Mode | Sessions per build | Baseline proof time | Changed proof time | Baseline peak RSS | Changed peak RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| [#3050](https://github.com/succinctlabs/sp1/pull/3050) outer Poseidon2 | 2× Groth16 | 2 | 92.851 s | 92.279 s | 21.32 GiB | 20.93 GiB |
| [#3050](https://github.com/succinctlabs/sp1/pull/3050) outer Poseidon2 | 2× PLONK | 2 | 100.745 s | 99.382 s | 20.76 GiB | 20.71 GiB |

## PLONK host peak during the grinding comparison

A separate CUPTI capture used the same installed release binaries and recorded both verified proofs. The combined host RSS peak occurred 12.073 s before the first grinding kernel of the repeat proof on the CUDA baseline and 11.951 s before it with parallel grinding. The six grinding launches totaled 2.622 s and 0.025 s, respectively. [Grinding measurements](https://github.com/succinctlabs/sp1/pull/3049)

## Groth16 stage timing for the Poseidon2 change

Two additional alternating SDK sessions per build ran with close-event timing for the recursion worker. Each session produced two verified proofs. These medians summarize four individual RSP proofs per build. The three stages run sequentially. Other SDK time is the remainder of each proof call, including core and recursive compression.

| Per-proof stage | CUDA baseline | With outer Poseidon2 |
| --- | ---: | ---: |
| Shrink proof | 0.216 s | 0.206 s |
| Outer STARK wrap proof | 5.050 s | 1.921 s |
| Final Groth16 call | 4.920 s | 4.810 s |
| Other SDK proof time | 40.406 s | 40.138 s |

The instrumented median two-proof session took 101.984 s on the baseline and 94.576 s with outer Poseidon2 (2/2 faster). The corresponding host peaks were 20.97 and 21.43 GiB. The three uninstrumented Groth16 comparisons of Poseidon2 by itself all favored the baseline. End-to-end Groth16 timing therefore varied across the two experiments.

In all four sessions the host RSS peak preceded the second shrink proof by at least 10.3 s. This uses the final RSS file write and last sample time to bound the latest possible peak against the server span timestamps.

The last commit only changes Groth16. A separate two-proof PLONK session at that exact head verified in 144.235 s at 17.22 GiB.

## Published changes together

A local build applied the 9 independent PRs to the published CUDA wrapper at `92d01c0cd`. The original CUDA PR at `6f14261e8` served as the control. Each build ran one fresh SDK session per mode. [#3046 at edf155abb](https://github.com/succinctlabs/sp1/pull/3046) · [#3047 at ff5931f20](https://github.com/succinctlabs/sp1/pull/3047) · [#3048 at 98a1e4cca](https://github.com/succinctlabs/sp1/pull/3048) · [#3049 at 505caa944](https://github.com/succinctlabs/sp1/pull/3049) · [#3050 at c6705736b](https://github.com/succinctlabs/sp1/pull/3050) · [#3051 at 84e2ecd49](https://github.com/succinctlabs/sp1/pull/3051) · [#3052 at 7aa669bcb](https://github.com/succinctlabs/sp1/pull/3052) · [#3054 at a32b80ea4](https://github.com/succinctlabs/sp1/pull/3054) · [#3055 at 868386197](https://github.com/succinctlabs/sp1/pull/3055)

| Change | Mode | Sessions per build | Baseline proof time | Changed proof time | Baseline peak RSS | Changed peak RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Combined review branches | Core | 1 | 30.893 s | 21.168 s | 12.84 GiB | 10.28 GiB |
| Combined review branches | Compressed | 1 | 40.652 s | 40.165 s | 13.58 GiB | 10.57 GiB |
| Combined review branches | 2× Groth16 | 1 | 104.537 s | 97.676 s | 20.64 GiB | 13.00 GiB |
| Combined review branches | 2× PLONK | 1 | 138.536 s | 103.264 s | 19.86 GiB | 14.58 GiB |

Across the four RSP sessions, SDK proof time totaled 314.618 s before and 262.273 s with the review changes (16.6% saved). The largest combined host RSS went from 20.64 to 14.58 GiB (29.4% saved).

During the RSP sessions, NVIDIA process telemetry sampled other applications every two seconds while the proving server was visible on the GPU. Summed streaming-multiprocessor utilization for those applications averaged 0% per session on the control and 0% on the changed build.

[Individual verified RSP sessions, source commits, binaries, timings and RSS samples at peak](sdk-rsp-pr-trials.csv)
