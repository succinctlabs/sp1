mod bigint;
mod bls12381;
mod bn254;
mod ed25519;
mod fp;
mod halt;
mod io;
mod keccak_permute;
mod memory;
mod secp256k1;
mod sha_compress;
mod sha_extend;
mod sys;
mod uint256_mul;
mod unconstrained;
#[cfg(feature = "verify")]
mod verify;

pub use bigint::*;
pub use bls12381::*;
pub use bn254::*;
pub use ed25519::*;
pub use fp::*;
pub use halt::*;
pub use io::*;
pub use keccak_permute::*;
pub use memory::*;
pub use secp256k1::*;
pub use sha_compress::*;
pub use sha_extend::*;
pub use sys::*;
pub use uint256_mul::*;
pub use unconstrained::*;
#[cfg(feature = "verify")]
pub use verify::*;

/// These codes MUST match the codes in `core/src/runtime/syscall.rs`. There is a derived test
/// that checks that the enum is consistent with the syscalls.

/// Halts the program.
pub const HALT: u32 = 0x00_00_00_00;

/// Writes to a file descriptor. Currently only used for `STDOUT/STDERR`.
pub const WRITE: u32 = 0x00_00_00_02;

/// Enter an unconstrained execution block.
pub const ENTER_UNCONSTRAINED: u32 = 0x00_00_00_03;

/// Exit an unconstrained execution block.
pub const EXIT_UNCONSTRAINED: u32 = 0x00_00_00_04;

/// Executes `SHA_EXTEND`.
pub const SHA_EXTEND: u32 = 0x00_30_01_05;

/// Executes `SHA_COMPRESS`.
pub const SHA_COMPRESS: u32 = 0x00_01_01_06;

/// Executes `ED_ADD`.
pub const ED_ADD: u32 = 0x00_01_01_07;

/// Executes `ED_DECOMPRESS`.
pub const ED_DECOMPRESS: u32 = 0x00_00_01_08;

/// Executes `KECCAK_PERMUTE`.
pub const KECCAK_PERMUTE: u32 = 0x00_01_01_09;

/// Executes `SECP256K1_ADD`.
pub const SECP256K1_ADD: u32 = 0x00_01_01_0A;

/// Executes `SECP256K1_DOUBLE`.
pub const SECP256K1_DOUBLE: u32 = 0x00_00_01_0B;

/// Executes `K256_DECOMPRESS`.
pub const SECP256K1_DECOMPRESS: u32 = 0x00_00_01_0C;

/// Executes `BN254_ADD`.
pub const BN254_ADD: u32 = 0x00_01_01_0E;

/// Executes `BN254_DOUBLE`.
pub const BN254_DOUBLE: u32 = 0x00_00_01_0F;

/// Executes the `COMMIT` precompile.
pub const COMMIT: u32 = 0x00_00_00_10;

/// Executes the `COMMIT_DEFERRED_PROOFS` precompile.
pub const COMMIT_DEFERRED_PROOFS: u32 = 0x00_00_00_1A;

/// Executes the `VERIFY_SP1_PROOF` precompile.
pub const VERIFY_SP1_PROOF: u32 = 0x00_00_00_1B;

/// Executes `HINT_LEN`.
pub const HINT_LEN: u32 = 0x00_00_00_F0;

/// Executes `HINT_READ`.
pub const HINT_READ: u32 = 0x00_00_00_F1;

/// Executes `BLS12381_DECOMPRESS`.
pub const BLS12381_DECOMPRESS: u32 = 0x00_00_01_1C;

/// Executes the `UINT256_MUL` precompile.
pub const UINT256_MUL: u32 = 0x00_01_01_1D;

/// Executes the `BLS12381_ADD` precompile.
pub const BLS12381_ADD: u32 = 0x00_01_01_1E;

/// Executes the `BLS12381_DOUBLE` precompile.
pub const BLS12381_DOUBLE: u32 = 0x00_00_01_1F;

/// Executes the `BLS12_381_FPMUL` precompile.
pub const BLS12381_FPMUL: u32 = 0x00_01_01_20;

/// Executes the `BLS12_381_FPADD` precompile.
pub const BLS12381_FPADD: u32 = 0x00_01_01_21;
