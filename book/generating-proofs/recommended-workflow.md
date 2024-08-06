# Recommended Workflow for Developing with SP1

We recommend the following workflow for developing with SP1.

## Step 1: Iterate on your program with execution only 

While iterating on your SP1 program, you should **only execute** the program with the RISC-V runtime. This will allow you to verify the correctness of your program and test the `SP1Stdin` as well as the `SP1PublicValues` that are returned, without having to generate a proof (which can be slow and/or expensive). If the execution of your program succeeds, then proof generation should succeed as well!

```rust,noplayground
{{#include ../../examples/fibonacci/script/bin/execute.rs}}
```

Note that printing out the total number of executed cycles and the full execution report provides helpful insight into proof generation latency and cost either for local proving or when using the prover network.

**Crate Setup:** We recommend that your program crate that defines the `main` function (around which you wrap the `sp1_zkvm::entrypoint!` macro) should be kept minimal. Most of your business logic should be in a separate crate (in the same repo/workspace) that can be tested independently and that is not tied to the SP1 zkVM. This will allow you to unit test your program logic without having to worry about the `zkvm` compilation target. This will also allow you to efficient reuse types between your program crate and your crate that generates proofs.

## Step 2: Generate proofs 

After you have iterated on your program and finalized that it works correctly, you can generate proofs for your program for final end to end testing or production use.

### Generating proofs on the prover network (recommended)

Using Succinct's prover prover network will generally be faster and cheaper than local proving, as it parallelizes proof generation amongst multiple machines and also uses SP1's GPU prover that is not yet available for local proving. Follow the [setup instructions](./prover-network.md) to get started with the prover network. Using the prover network only requires adding 1 environment variable from a regular SP1 proof generation script with the `ProverClient`.

There are a few things to keep in mind when using the prover network.

### Prover Network FAQ

#### Benchmarking latency on the prover network

The prover network currently parallelizes proof generation across multiple machines. This means the latency of proof generation does not scale linearly with the number of cycles of your program, but rather with the number of cycles of your program divided by the number of currently available machines on the prover network. 

Our prover network currently has limited capacity because it is still in beta. If you have an extremely latency sensitive use-case and you want to figure out the **minimal latency possible** for your program, you should [reach out to us](https://partner.succinct.xyz/) and we can onboard you to our reserved capacity cluster that has a dedicated instances that can significantly reduce latency.

#### Costs on the prover network

The cost of proof generation on the prover network scales approximately linearly with the number of cycles of your program (along with the number of `syscalls` that your program makes). For larger workloads with regular proof frequency (like rollups and light clients), we can offer discounted pricing. To figure out how much your program will cost to prove, you can get [in touch with us](https://partner.succinct.xyz/) to discuss pricing options.

Note that **latency is not the same as cost**, because we parallelize proof generation across multiple machines, so two proofs with the same latency can be using a different number of machines, impacting the cost.

#### Benchmarking on small vs. large programs

In SP1, there is a fixed overhead for proving that is independent of your program's cycle count. This means that benchmarking on *small programs* is not representative of the performance of larger programs. To get an idea of the scale of programs for real-world workloads, you can refer to our [benchmarking blog post](https://blog.succinct.xyz/sp1-production-benchmarks) and also some numbers below:

* An average Ethereum block can be between 100-500M cycles (including merkle proof verification for storage and execution of transactions) with our `keccak` and `secp256k1` precompiles.
* For a Tendermint light client, the average cycle count can be between 10M and 50M cycles (including our ed25519 precompiles).
* We consider programs with <2M cycles to be "small" and by default, the fixed overhead of proving will dominate the proof latency. If latency is incredibly important for your use-case, we can specialize the prover network for your program if you reach out to us.

Note that if you generate PLONK proofs on the prover network, you will encounter a fixed overhead of 90 seconds for the STARK -> SNARK wrapping step. We're actively working on reducing this overhead in our next release.

#### On-Demand vs. Reserved Capacity

The prover network is currently in beta and has limited capacity. For high volume use-cases, we can offer discounted pricing and a reserved capacity cluster that has a dedicated instances that can significantly reduce latency and have higher throughput and guaranteed SLAs.

### Generating proofs locally

If you want to generate proofs locally, you can use the `sp1_sdk` crate to generate proofs locally as outlined in the [Basics](./basics.md) section. By default, the `ProverClient` will generate proofs locally using your CPU. Check out the hardware requirements for locally proving [here](../getting-started/hardware-requirements.md#local-proving).