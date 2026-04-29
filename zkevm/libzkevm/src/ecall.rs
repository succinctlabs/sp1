//! SP1 syscall number re-exports.
//!
//! SP1's syscall ABI (see `crates/zkvm/entrypoint/src/syscalls/`) is:
//!
//! * `ecall` instruction with the syscall number in `t0`
//! * arguments in `a0`, `a1`, `a2`, ... (RISC-V calling convention)
//! * return value (when present) in `t0` (lateout) or via an `a0` out-pointer
//!
//! For halt / write / hint we delegate to `sp1-zkvm`'s high-level
//! `syscall_*` wrappers (which also feed the public-values hasher and
//! commit the digest before HALT). The cryptographic precompiles route
//! through patched RustCrypto / curve crates whose inner primitives
//! call the relevant `*_ADD`, `*_DOUBLE`, `*_DECOMPRESS`, `*_FP{,2}_*`
//! syscalls directly via `sp1-lib` — no hand-rolled `ecall` here.

/// SP1 syscall numbers — re-exported from `sp1-zkvm` so the two ABIs
/// cannot drift. Source of truth:
/// `crates/zkvm/entrypoint/src/syscalls/mod.rs`.
pub mod sp1 {
    pub use sp1_zkvm::syscalls::{
        BLS12381_ADD, BLS12381_DECOMPRESS, BLS12381_DOUBLE, BLS12381_FP2_ADD, BLS12381_FP2_MUL,
        BLS12381_FP2_SUB, BLS12381_FP_ADD, BLS12381_FP_MUL, BLS12381_FP_SUB, BN254_ADD,
        BN254_DOUBLE, BN254_FP2_ADD, BN254_FP2_MUL, BN254_FP2_SUB, BN254_FP_ADD, BN254_FP_MUL,
        BN254_FP_SUB, HALT, HINT_LEN, HINT_READ, KECCAK_PERMUTE, POSEIDON2, SECP256K1_ADD,
        SECP256K1_DECOMPRESS, SECP256K1_DOUBLE, SECP256R1_ADD, SECP256R1_DECOMPRESS,
        SECP256R1_DOUBLE, SHA_COMPRESS, SHA_EXTEND, WRITE,
    };
}
