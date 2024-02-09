mod ed25519;
mod halt;
mod io;
mod keccak_permute;
mod secp256k1;
mod sha_compress;
mod sha_extend;
mod sys;
mod unconstrained;

#[cfg(not(feature = "syscall-interface"))]
mod syscall_def {
    pub use super::ed25519::*;
    pub use super::halt::*;
    pub use super::io::*;
    pub use super::keccak_permute::*;
    pub use super::secp256k1::*;
    pub use super::sha_compress::*;
    pub use super::sha_extend::*;
    pub use super::sys::*;
    pub use super::unconstrained::*;
}

#[cfg(not(feature = "syscall-interface"))]
pub use syscall_def::*;

#[cfg(feature = "syscall-interface")]
extern "C" {
    pub fn syscall_halt() -> !;
    pub fn syscall_write(fd: u32, write_buf: *const u8, nbytes: usize);
    pub fn syscall_read(fd: u32, read_buf: *mut u8, nbytes: usize);
    pub fn syscall_sha256_extend(w: *mut u32);
    pub fn syscall_sha256_compress(w: *mut u32, state: *mut u32);
    pub fn syscall_ed_add(p: *mut u32, q: *mut u32);
    pub fn syscall_ed_decompress(point: &mut [u8; 64]);
    pub fn syscall_secp256k1_add(p: *mut u32, q: *const u32);
    pub fn syscall_secp256k1_double(p: *mut u32);
    pub fn syscall_secp256k1_decompress(point: &mut [u8; 64], is_odd: bool);
    pub fn syscall_keccak_permute(state: *mut u64);
    pub fn syscall_enter_unconstrained() -> bool;
    pub fn syscall_exit_unconstrained();
}

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

/// Writes to a file descriptor. Currently only used for `STDOUT/STDERR`.
pub const WRITE: u32 = 999;
