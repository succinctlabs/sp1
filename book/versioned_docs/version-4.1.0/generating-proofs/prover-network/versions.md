# Supported Versions

The prover network currently only supports specific versions of SP1:

| Version | Description                                                      |
| ------- | ---------------------------------------------------------------- |
| v4.X.X  | V4 Release. Latest performant & production ready version.        |

`X` denotes that any minor and patch version is supported (e.g. `v4.0.1`, `v4.1.0`).

If you submit a proof request to the prover network and you are not using a supported version, you will receive an error message.

## Changing versions

You must switch to a supported version before submitting a proof. To do so, replace the `sp1-zkvm` version in your program's `Cargo.toml`:

```toml
[dependencies]
sp1-zkvm = "4.0.0"
```

replace the `sp1-sdk` version in your script's `Cargo.toml`:

```toml
[dependencies]
sp1-sdk = "4.0.0"
```

Re-build your program and script, and then try again.
