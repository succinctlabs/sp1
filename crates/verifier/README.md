# SP1 Verifier

This crate provides verifiers for SP1 Groth16 and Plonk zero-knowledge proofs. These proofs are expected
to be generated using the [SP1 SDK](../sdk).

## Features

Groth16 proof verification is supported in completely no-std environments. 

Plonk proof verification requires randomness, so it requires a `getrandom` implementation in the 
runtime. Environments like wasm and the sp1 zkvm are capable of providing this. 

We provide the `getrandom` feature flag for this purpose, which is enabled by default. 

# Acknowledgements

Adapted from [@Bisht13's](https://github.com/Bisht13/gnark-bn254-verifier) `gnark-bn254-verifier` crate.

