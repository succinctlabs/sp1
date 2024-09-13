# Supported Versions

The prover network currently only supports specific versions of SP1:

| Version | Description                                                                                                                                              |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| v2.X.X  | Audited, production ready version.                                                                                                                       |
| v3.X.X  | Pre-release version with enhanced performance, currently being audited. **Recommended for benchmarking or testing, not recommended for production use.** |

`X` denotes that any minor and patch version is supported (e.g. `v2.1.0`, `v2.1.1`).

If you submit a proof request to the prover network and you are not using a supported version, you will receive an error message.

## Changing versions

You must switch to a supported version before submitting a proof. To do so, replace the `sp1-zkvm` version in your progam's `Cargo.toml`:

```toml
[dependencies]
sp1-zkvm = "2.0.0"
```

replace the `sp1-sdk` version in your script's `Cargo.toml`:

```toml
[dependencies]
sp1-sdk = "2.0.0"
```

Re-build your program and script, and then try again.
