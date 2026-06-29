//! Precompile bodies implementing the eth-act `zkvm_accelerators.h` ABI.
//!
//! Layout: one module per accelerator family. Each export has a signature
//! *exactly* matching the C header.
//!
//! | C function                       | SP1 path                                                                    |
//! |----------------------------------|------------------------------------------------------------------------------|
//! | `zkvm_keccak256`                 | patched `tiny-keccak`: routes `keccakf` to `KECCAK_PERMUTE`                 |
//! | `zkvm_sha256`                    | patched `sha2`: `SHA_EXTEND` + `SHA_COMPRESS`                               |
//! | `zkvm_ripemd160`                 | software via stock `ripemd` crate                                           |
//! | `zkvm_secp256k1_ecrecover`       | patched `k256` `recover_from_prehash` (uses `FD_ECRECOVER_HOOK` in zkvm)    |
//! | `zkvm_secp256k1_verify`          | patched `k256` ECDSA verify; routes through `SECP256K1_*` syscalls          |
//! | `zkvm_secp256r1_verify`          | patched `p256` ECDSA verify; routes through `SECP256R1_*` syscalls          |
//! | `zkvm_bn254_g1_add`/`mul`        | patched `substrate-bn`; routes through `BN254_ADD`/`DOUBLE`                 |
//! | `zkvm_bn254_pairing`             | patched `substrate-bn` `pairing_batch`                                      |
//! | `zkvm_bls12_g{1,2}_{add,msm}`    | patched `bls12_381` over `BLS12381_*` syscalls                              |
//! | `zkvm_bls12_pairing`             | patched `bls12_381` `multi_miller_loop` + `final_exponentiation`            |
//! | `zkvm_bls12_map_fp{,2}_to_g{1,2}`| patched `bls12_381` `MapToCurve` (experimental) + `clear_cofactor`          |
//! | `zkvm_modexp`                    | software via `num-bigint-dig::BigUint::modpow`                              |
//! | `zkvm_blake2f`                   | software F compression vendored inline per RFC 7693 §3.2                    |
//! | `zkvm_kzg_point_eval`            | `kzg-rs` (Ethereum trusted setup baked in via `include_bytes!`)             |

pub mod blake2f;
pub mod bls12_381;
pub mod bn254;
pub mod hash;
pub mod kzg;
pub mod modexp;
pub mod secp256k1;
pub mod secp256r1;
pub mod types;
