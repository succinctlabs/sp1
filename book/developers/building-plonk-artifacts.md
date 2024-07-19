# Building PLONK Artifacts

To build the production Plonk Bn254 artifacts from scratch, you can use the `Makefile` inside the `prover` directory.

```shell,noplayground
cd prover
RUST_LOG=info make build-plonk-bn254
```