# Ethereum RSP proof benchmarks

## Guest and measurement

The checked-in RSP guest re-executed Ethereum mainnet block 21,740,136, with 88 transactions and 5,524,782 gas. The core proof had 102 shards at `HEIGHT_THRESHOLD=262144`. Main produced 36 core shards for the same block at the default height. Each proof returned the expected 748-byte header. Its Keccak-256 hash was `0xd42ec18b0b56fed31aa3976057fae903251f7d409651335780ead557502d0413`. [Ethereum block](https://eth.blockscout.com/block/21740136)

Runs used one RTX 4090 and a Ryzen 9 5950X. The same release SDK client launched each matching release server from `~/.sp1/bin` and independently verified the proof. Time covers the SDK proof call. Host RSS is the largest simultaneous sum for the client and server, sampled with a 4 ms sleep from startup through shutdown.

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

## SHA-256 control for RISC-V machine reuse

The initial three-session SHA-256 core comparison suggested a 34.2% reduction. Across ten alternating pairs on the same eight-shard input, core fell from 2.770 to 2.557 s (7.7%) and compressed from 4.670 to 4.415 s (5.5%). The PR was faster in all twenty pairs. Constructing the RISC-V machine took 237 ms per request. Cloning the configured machine took 0.019 ms. The original baseline varied from 6.784 to 14.963 s, and the multi-second difference did not reproduce. [All forty proofs and the construction benchmark](https://github.com/succinctlabs/sp1/pull/3046)

## The two combined CUDA prover rounds

The original CUDA wrapper at `6f14261e8`, round one at `03adf8d0c`, and round two at `c98af6e40` all used the GPU for gnark. Round one and round two ran consecutively on the same 102-shard block, once per build and mode. Each wrapping session verified two proofs with Go defaults. Both the original CUDA PR core and compressed figures use one fresh session. The original CUDA PR wrapping figures come from the three earlier sessions per mode in the outer STARK comparison below.

| Mode | CUDA PR baseline time / peak | Round 1 time / peak | Round 2 time / peak | Time saved in round 2 | Peak RSS saved in round 2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Core | 22.203 s / 12.61 GiB | 20.868 s / 6.74 GiB | 18.462 s / 5.37 GiB | 11.5% | 20.4% |
| Compressed | 39.214 s / 13.77 GiB | 39.725 s / 7.84 GiB | 29.001 s / 5.47 GiB | 27.0% | 30.2% |
| 2× Groth16 | 98.198 s / 21.19 GiB | 96.987 s / 14.90 GiB | 67.418 s / 8.55 GiB | 30.5% | 42.6% |
| 2× PLONK | 107.547 s / 20.69 GiB | 104.530 s / 14.54 GiB | 75.506 s / 9.55 GiB | 27.8% | 34.3% |

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

### CPU multiplication and lookup generation

Each of nine alternating release-process pairs populated 250,000 multiplication rows with identical checksums. Removing the temporary vectors reduced the median per trace row from 240.0 to 157.2 ns and per dependency row from 456.0 to 390.1 ns. Core RSP proof time increased in all three end-to-end pairs.

A second change skipped byte lookups that the CPU trace writer immediately discarded. Five release-process pairs replayed each captured shard using 16 Rayon threads. Both builds produced the same digest of every field element and sorted byte-lookup multiplicity for every affected AIR present. The table gives median time to generate the trace matrices. The installed-server RSP compressed proof took longer in each of its three pairs.

| Captured record | AIRs | Matched trace cells | Main | Skip discarded lookups |
| --- | ---: | ---: | ---: | ---: |
| RSP | 12 | 49,236,288 | 30.4 ms | 29.1 ms |
| Four-million-iteration Fibonacci | 7 | 282,934,016 | 150.7 ms | 139.1 ms |

## LogUp on two RSP shard sizes

Two additional rotated pairs measured compressed time and host RSS at each shard height. A separate debug run on the same release binary counted the main-codeword releases during FRI. [LogUp device-memory PR](https://github.com/succinctlabs/sp1/pull/3052)

| RSP core shards | Main compressed time | PR compressed time | Main peak RSS | PR peak RSS | Codewords released in separate PR run |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 102 | 39.358 s | 39.393 s | 14.33 GiB | 14.03 GiB | 0 |
| 36 | 22.907 s | 22.652 s | 16.16 GiB | 16.24 GiB | 0 |

## CUDA wrapping with the two outer STARK changes

The baseline for this table is the CUDA wrapper at `6f14261e8`. Each changed build applies one main-branch PR. Both the STARK and the final prover used the GPU, with the default Go runtime. Each session verified two RSP proofs.

| Change | Mode | Sessions per build | Baseline proof time | Changed proof time | Baseline peak RSS | Changed peak RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| [#3049](https://github.com/succinctlabs/sp1/pull/3049) grinding | 2× Groth16 | 3 | 98.198 s | 92.321 s | 21.19 GiB | 20.94 GiB |
| [#3049](https://github.com/succinctlabs/sp1/pull/3049) grinding | 2× PLONK | 3 | 107.547 s | 99.943 s | 20.69 GiB | 20.93 GiB |
| [#3050](https://github.com/succinctlabs/sp1/pull/3050) Poseidon2 | 2× Groth16 | 3 | 98.198 s | 100.280 s | 21.19 GiB | 21.12 GiB |
| [#3050](https://github.com/succinctlabs/sp1/pull/3050) Poseidon2 | 2× PLONK | 3 | 107.547 s | 102.152 s | 20.69 GiB | 20.50 GiB |

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

[Individual verified RSP sessions, source commits, binaries, timings and RSS samples at peak](sdk-rsp-pr-trials.csv)
