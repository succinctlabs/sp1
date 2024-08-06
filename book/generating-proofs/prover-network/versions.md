# Supported Versions

The prover network currently only supports specific versions of SP1:

| Environment | RPC URL                    | Supported Version |
| ----------- | -------------------------- | ----------------- |
| Prod        | `https://rpc.succinct.xyz` | v1.1.0            |

If you submit a proof request to the prover network and your are not using the supported version, you will receive an error message.

## Changing versions

You must switch to a supported version before submitting a proof. To do so, replace the `sp1-zkvm` version in your progam's `Cargo.toml`:

```toml
[dependencies]
sp1-zkvm = "1.1.0"
```

replace the `sp1-sdk` version in your script's `Cargo.toml`:

```toml
[dependencies]
sp1-sdk = "1.1.0"
```

Re-build your program and script, and then try again.
