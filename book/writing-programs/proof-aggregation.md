# Proof Aggregation

SP1 supports proof aggregation and recursion, which allows you to verify proofs within a proof. Use cases include:

- Reducing on-chain verification costs by aggregating multiple proofs into a single proof.
- Proving logic that is split into multiple proofs, such as proving a statement about a rollup's state transition function.

**For an example of how to use proof aggregation and recursion in SP1, refer to the [aggregation example](https://github.com/succinctlabs/sp1/blob/main/examples/aggregation/script/src/main.rs).**

## Verifying Proofs inside the zkVM 

To verify a proof inside the zkVM, you can use the `sp1_zkvm::lib::verify_proof` function.

```rust,noplayground
sp1_zkvm::lib::verify_proof(vkey, public_values_digest);
```

**You do not need to pass in the proof as input into the syscall, as the proof will automatically be read for the proof input stream by the prover.**

## Generating Proofs with Aggregation

To provide an existing proof as input to the SP1 zkVM, you can use the existing `SP1Stdin` object
which is already used for all inputs to the zkVM.

```rust,noplayground
# Generating proving key and verifying key.
let (input_pk, input_vk) = client.setup(PROOF_INPUT_ELF);
let (aggregation_pk, aggregation_vk) = client.setup(AGGREGATION_ELF);

// Generate a proof that will be recursively verified / aggregated.
let mut stdin = SP1Stdin::new();
let input_proof = client
    .prove(&input_pk, stdin)
    .compressed()
    .run()
    .expect("proving failed");

// Create a new stdin object to write the proof and the corresponding verifying key to.
let mut stdin = SP1Stdin::new();
stdin.write_proof(proof, input_vk);

// Generate a proof that will recusively verify / aggregate the input proof.
let aggregation_proof = client
    .prove(&aggregation_pk, stdin)
    .compressed()
    .run()
    .expect("proving failed");

```

