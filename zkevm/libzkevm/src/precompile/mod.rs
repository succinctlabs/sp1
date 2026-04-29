//! Precompile stubs implementing the eth-act `zkvm_accelerators.h` ABI.
//!
//! Layout: one module per accelerator family.
//!
//! Every export has signature *exactly* matching the C header. Bodies are
//! stubs — they validate input pointers, then either issue a placeholder
//! `ecall` (`0xDEAD_xxxx`, see [`crate::ecall::placeholder`]) or fall through
//! to returning `ZKVM_EFAIL`. **A wrong precompile is worse than no
//! precompile**, so do not "fix" a stub by inventing crypto here — replace
//! it with a correct dispatch over real SP1 syscalls instead.
//!
//! Suggested mapping (informational, not implemented):
//!
//! | C function                       | Likely SP1 path                                                              |
//! |----------------------------------|------------------------------------------------------------------------------|
//! | `zkvm_keccak256`                 | loop over `KECCAK_PERMUTE` with sponge padding                              |
//! | `zkvm_sha256`                    | loop over `SHA_EXTEND` + `SHA_COMPRESS` with MD padding                     |
//! | `zkvm_secp256k1_ecrecover`       | host hook (see SP1's `FD_ECRECOVER_HOOK`) + `SECP256K1_ADD/DOUBLE` verify   |
//! | `zkvm_secp256k1_verify`          | scalar mul via `SECP256K1_ADD/DOUBLE`, no new syscall needed                |
//! | `zkvm_secp256r1_verify`          | scalar mul via `SECP256R1_ADD/DOUBLE`                                       |
//! | `zkvm_bn254_g1_add`/`mul`        | direct dispatch to `BN254_ADD`/`BN254_DOUBLE` with windowed scalar mul      |
//! | `zkvm_bn254_pairing`             | composed from `BN254_FP{2}_*` precompiles + Miller loop in software        |
//! | `zkvm_bls12_g1_add`/`g1_msm`/...| direct dispatch to `BLS12381_*` precompiles                                 |
//! | `zkvm_bls12_pairing`             | composed from `BLS12381_FP{2}_*` precompiles                                |
//! | `zkvm_bls12_map_fp{,2}_to_g{1,2}`| no SP1 syscall — needs new runtime support (or sw impl on top of FP ops)   |
//! | `zkvm_modexp`                    | no SP1 syscall — needs new runtime support (or sw bigint)                  |
//! | `zkvm_blake2f`                   | no SP1 syscall — needs new runtime support                                 |
//! | `zkvm_kzg_point_eval`            | composed from `BLS12381_*` precompiles + KZG verifier in software          |
//! | `zkvm_ripemd160`                 | no SP1 syscall — software impl is acceptable; not perf-critical for L1 STF |

pub mod blake2f;
pub mod bls12_381;
pub mod bn254;
pub mod hash;
pub mod kzg;
pub mod modexp;
pub mod secp256k1;
pub mod secp256r1;
pub mod types;
