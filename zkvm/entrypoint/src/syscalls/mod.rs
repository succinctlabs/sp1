mod blake3_compress;
mod bn254;
mod ed25519;
mod halt;
mod io;
mod keccak_permute;
mod memory;
mod secp256k1;
mod sha_compress;
mod sha_extend;
mod sys;
mod unconstrained;

pub use bn254::*;
pub use ed25519::*;
pub use halt::*;
pub use io::*;
pub use keccak_permute::*;
pub use memory::*;
pub use secp256k1::*;
pub use sha_compress::*;
pub use sha_extend::*;
pub use sys::*;
pub use unconstrained::*;

/// These codes MUST match the codes in `core/src/runtime/syscall.rs`. There is a derived test
/// that checks that the enum is consistent with the syscalls.

/// Halts the program.
pub const HALT: u32 = 0x01_00_00_00;

/// Loads a word supplied from the prover.
pub const LWA: u32 = 0x00_00_00_01;

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

/// Executes `BLAKE3_COMPRESS_INNER`.
pub const BLAKE3_COMPRESS_INNER: u32 = 0x00_38_01_0D;

/// Executes `BN254_ADD`.
pub const BN254_ADD: u32 = 0x00_01_01_0E;

/// Executes `BN254_DOUBLE`.
pub const BN254_DOUBLE: u32 = 0x00_00_01_0F;
