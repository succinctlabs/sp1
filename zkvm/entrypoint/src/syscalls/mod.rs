mod blake3_compress;
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

/// Halts the program.
pub const HALT: u32 = 100;

/// Loads a word supplied from the prover.
pub const LWA: u32 = 101;

/// Executes `SHA_EXTEND`.
pub const SHA_EXTEND: u32 = 102;

/// Executes `SHA_COMPRESS`.
pub const SHA_COMPRESS: u32 = 103;

/// Executes `ED_ADD`.
pub const ED_ADD: u32 = 104;

/// Executes `ED_DECOMPRESS`.
pub const ED_DECOMPRESS: u32 = 105;

/// Executes `KECCAK_PERMUTE`.
pub const KECCAK_PERMUTE: u32 = 106;

/// Executes `SECP256K1_ADD`.
pub const SECP256K1_ADD: u32 = 107;

/// Executes `SECP256K1_DOUBLE`.
pub const SECP256K1_DOUBLE: u32 = 108;

/// Executes `K256_DECOMPRESS`.
pub const SECP256K1_DECOMPRESS: u32 = 109;

/// Enter an unconstrained execution block.
pub const ENTER_UNCONSTRAINED: u32 = 110;

/// Exit an unconstrained execution block.
pub const EXIT_UNCONSTRAINED: u32 = 111;

/// Executes `BLAKE3_COMPRESS_INNER`.
pub const BLAKE3_COMPRESS_INNER: u32 = 112;

/// Executes `FRI_FOLD`.
pub const FRI_FOLD: u32 = 113;

/// Writes to a file descriptor. Currently only used for `STDOUT/STDERR`.
pub const WRITE: u32 = 999;
