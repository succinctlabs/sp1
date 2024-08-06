# Prover Options

The prover options can be configured using a "builder" pattern after creating a `ProverClient` and 
calling `prove` on it.

For a full list of options, see the [SP1 SDK](https://github.com/succinctlabs/sp1/blob/dev/sdk/src/action.rs).

## Core (Default)

The default prover mode generates a list of STARK proofs that in aggregate have size proportional to
 the size of the execution. Use this in settings where you don't care about **verification cost / proof size**.

```rust,noplayground
let client = ProverClient::new();
client.prove(&pk, stdin).run().unwrap();
```

## Compressed

The compressed prover mode generates STARK proofs that have constant size. Use this in settings where you
care about **verification cost / proof size**.

```rust,noplayground
let client = ProverClient::new();
client.prove(&pk, stdin).compressed().run().unwrap();
```

## PLONK

> WARNING: The PLONK prover requires around 128GB of RAM and is only guaranteed to work on official releases of SP1.

The PLONK prover mode generates a SNARK proof with extremely small proof size and low verification cost.
This mode is necessary for generating proofs that can be verified onchain for around ~300k gas.

```rust,noplayground
let client = ProverClient::new();
client.prove(&pk, stdin).plonk().run().unwrap();
```
