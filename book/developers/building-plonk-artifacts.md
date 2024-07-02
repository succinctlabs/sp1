# Building Plonk BN254 Artifacts

To build the production Plonk Bn254 artifacts from scratch, you can use the `Makefile` inside the `prover` directory.

```shell,noplayground
cd prover
RUST_LOG=info make build-plonk-bn254
```

## Non-production builds

For quickly building the plonk artifacts, you can run `cargo test` with additional flags to speed up the build process.

```shell,noplayground
SP1_DEV=true FRI_QUERIES=1 cargo test --release test_e2e_prove_plonk
```

The generated artifacts should only be used for development and testing purposes.
