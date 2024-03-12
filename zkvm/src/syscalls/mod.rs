#[cfg(not(feature = "interface"))]
mod blake3_compress;
#[cfg(not(feature = "interface"))]
mod ed25519;
#[cfg(not(feature = "interface"))]
mod halt;
#[cfg(not(feature = "interface"))]
mod io;
#[cfg(not(feature = "interface"))]
mod keccak_permute;
#[cfg(not(feature = "interface"))]
mod memory;
#[cfg(not(feature = "interface"))]
mod secp256k1;
#[cfg(not(feature = "interface"))]
mod sha_compress;
#[cfg(not(feature = "interface"))]
mod sha_extend;
#[cfg(not(feature = "interface"))]
mod sys;
#[cfg(not(feature = "interface"))]
mod unconstrained;

#[cfg(not(feature = "interface"))]
mod syscall_def {
    pub use super::ed25519::*;
    pub use super::halt::*;
    pub use super::io::*;
    pub use super::keccak_permute::*;
    pub use super::memory::*;
    pub use super::secp256k1::*;
    pub use super::sha_compress::*;
    pub use super::sha_extend::*;
    pub use super::sys::*;
    pub use super::unconstrained::*;
}

#[cfg(feature = "interface")]
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
    pub fn syscall_blake3_compress_inner(p: *mut u32, q: *const u32);
    pub fn syscall_enter_unconstrained() -> bool;
    pub fn syscall_exit_unconstrained();
    pub fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8;
}

#[cfg(not(feature = "interface"))]
pub use syscall_def::*;

/// These codes MUST match the codes in `core/src/runtime/syscall.rs`.
/// TODO: is there a programmatic way to enforce this with clippy?

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
pub const SHA_EXTEND: u32 = 0x00_80_01_00;

/// Executes `SHA_COMPRESS`.
pub const SHA_COMPRESS: u32 = 0x00_80_01_01;

/// Executes `ED_ADD`.
pub const ED_ADD: u32 = 0x00_80_01_02;

/// Executes `ED_DECOMPRESS`.
pub const ED_DECOMPRESS: u32 = 0x00_80_01_03;

/// Executes `KECCAK_PERMUTE`.
pub const KECCAK_PERMUTE: u32 = 0x00_80_01_04;

/// Executes `SECP256K1_ADD`.
pub const SECP256K1_ADD: u32 = 0x00_80_01_05;

/// Executes `SECP256K1_DOUBLE`.
pub const SECP256K1_DOUBLE: u32 = 0x00_80_01_06;

/// Executes `K256_DECOMPRESS`.
pub const SECP256K1_DECOMPRESS: u32 = 0x00_80_01_07;

/// Executes `BLAKE3_COMPRESS_INNER`.
pub const BLAKE3_COMPRESS_INNER: u32 = 0x00_80_01_08;
