# Proof Generation Requirements

<div class="warning">
We recommend that developers who want to use SP1 for non-trivial programs generate proofs on our prover network. The prover network generates SP1 proofs across multiple machines, reducing latency and also runs SP1 on optimized hardware instances that result in faster + cheaper proof generation times.

We recommend that for any production benchmarking, you use the prover network to estimate latency and costs of proof generation.

</div>

## Local Proving

If you want to generate SP1 proofs locally, this section has an overview of the hardware requirements required. These requires depend on which [types of proofs](../generating-proofs/proof-types.md) you want to generate and can also change over time as the design of the zKVM evolves.

**The most important requirement is CPU for performance/latency and RAM to prevent running out of memory.**

|                | Mock / Network               | Core / Compress                    | Groth16 and PLONK (EVM) |
| -------------- | ---------------------------- | ---------------------------------- | ----------------------- |
| CPU            | 1+, single-core perf matters | 16+, more is better                | 16+, more is better     |
| Memory         | 8GB+, more is better         | 16GB+, more if you have more cores | 16GB+, more is better   |
| Disk           | 10GB+                        | 10GB+                              | 10GB+                   |
| EVM Compatible | ✅                           | ❌                                 | ✅                      |

### CPU

The execution & trace generation of the zkVM is mostly CPU bound, having a high single-core
performance is recommended to accelerate these steps. The rest of the prover is mostly bound by hashing/field operations
which can be parallelized with multiple cores.

### Memory

Our prover requires keeping large matrices (i.e., traces) in memory to generate the proofs. Certain steps of the prover
have a minimum memory requirement, meaning that if you have less than this amount of memory, the process will OOM.

This effect is most noticeable when using the Groth16 or PLONK provers.

### Disk

Disk is required to install the SP1 zkVM toolchain and to install the circuit artifacts, if you
plan to locally build the Groth16 or PLONK provers.

Furthermore, disk is used to checkpoint the state of the program execution, which is required to generate the proofs.
