# SP1 Verifier

This crate provides verifiers for Groth16 and Plonk zero-knowledge proofs.

Groth16 proof verification is supported in completely no-std environments. 

Plonk proof verification requires randomness, so it requires a `getrandom` implementation in the 
runtime. Environments like wasm and the sp1 zkvm are capable of providing this.

TODO: 
* Add some sample snippets demonstrating how to use the verifier in different environments.
* Should you really be verifying SP1 plonk proofs within sp1? If SP1's randomness is from fiat shamir,
I guess it should be fine ... but this seems like a subtle, bug-prone use case.

# Acknowledgements

Adapted from [@Bisht13's](https://github.com/Bisht13/gnark-bn254-verifier) `gnark-bn254-verifier` crate.

