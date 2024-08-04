# Recommended Workflow for Developing with SP1

## Step 1: Execution Only

We recommend that during the development of large programs (> 1 million cycles) you do not generate proofs each time.
Instead, you should have your script only execute the program with the RISC-V runtime and read `public_values`. Here is an example:

```rust,noplayground
{{#include ../../examples/fibonacci/script/bin/execute.rs}}
```

If the execution of your program succeeds, then proof generation should succeed as well! (Unless there is a bug in our zkVM implementation.)

## Step 2:Use Prover Network

> Note that benchmarking on *small programs* is not representative of the performance of larger programs. There is a fixed overhead for proving and

* We have proven programs with up to 20B cycles on the prover network (for context, proving the execution of an average Ethereum block, including merkle proof verification for storage, is around 300-400M cycles).

### Benchmarking on small vs. large programs

### Latency

### Cost

### On-Demand vs. Reserved Capacity

## Ballpark Estimates

## Local Proving When Needed