# Building Circuit Artifacts

To build the production Groth16 and PLONK Bn254 artifacts from scratch, you can use the `Makefile` inside the `prover` directory.

```shell,noplayground
cd prover
RUST_LOG=info make build-circuits
```
