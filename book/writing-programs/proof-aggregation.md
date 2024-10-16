# Proof Aggregation

SP1 supports proof aggregation and recursion, which allows you to verify an SP1 proof within SP1. Use cases include:

- Reducing on-chain verification costs by aggregating multiple SP1 proofs into a single SP1 proof.
- Proving logic that is split into multiple proofs, such as proving a statement about a rollup's state transition function by proving each block individually and aggregating these proofs to produce a final proof of a range of blocks.

**For an example of how to use proof aggregation and recursion in SP1, refer to the [aggregation example](https://github.com/succinctlabs/sp1/blob/main/examples/aggregation/script/src/main.rs).**

Note that to verify an SP1 proof inside SP1, you must generate a "compressed" SP1 proof (see [Proof Types](../generating-proofs/proof-types.md) for more details).

### When to use aggregation

Note that by itself, SP1 can already prove arbitrarily large programs by chunking the program's execution into multiple "shards" (contiguous batches of cycles) and generating proofs for each shard in parallel, and then recursively aggregating the proofs. Thus, aggregation is generally **not necessary** for most use-cases, as SP1's proving for large programs is already parallelized. However, aggregation can be useful for aggregating computations that require more than the zkVM's limited (~2GB) memory or for aggregating multiple SP1 proofs from different parties into a single proof to save on onchain verification costs.

## Verifying Proofs inside the zkVM

To verify a proof inside the zkVM, you can use the `sp1_zkvm::lib::verify::verify_proof` function.

```rust,noplayground
sp1_zkvm::lib::verify::verify_proof(vkey, public_values_digest);
```

**You do not need to pass in the proof as input into the syscall, as the proof will automatically be read for the proof input stream by the prover.**

Note that you must include the `verify` feature in your `Cargo.toml` for `sp1-zkvm` to be able to use the `verify_proof` function (like [this](https://github.com/succinctlabs/sp1/blob/main/examples/aggregation/program/Cargo.toml#L11)).

## Generating Proofs with Aggregation

To provide an existing proof as input to the SP1 zkVM, you can use the existing `SP1Stdin` object
which is already used for all inputs to the zkVM.

```rust,noplayground
# Generating proving key and verifying key.
let (input_pk, input_vk) = client.setup(PROOF_INPUT_ELF);
let (aggregation_pk, aggregation_vk) = client.setup(AGGREGATION_ELF);

// Generate a proof that will be recursively verified / aggregated. Note that we use the "compressed"
// proof type, which is necessary for aggregation.
let mut stdin = SP1Stdin::new();
let input_proof = client
    .prove(&input_pk, stdin)
    .compressed()
    .run()
    .expect("proving failed");

// Create a new stdin object to write the proof and the corresponding verifying key to.
let mut stdin = SP1Stdin::new();
stdin.write_proof(input_proof, input_vk);

// Generate a proof that will recursively verify / aggregate the input proof.
let aggregation_proof = client
    .prove(&aggregation_pk, stdin)
    .compressed()
    .run()
    .expect("proving failed");

```
