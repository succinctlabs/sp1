//! Precompiles for SP1 zkVM.
//!
//! Specifically, this crate contains user-friendly functions that call SP1 syscalls. Syscalls are
//! also declared here for convenience. In order to avoid duplicate symbol errors, the syscall
//! function impls must live in sp1-zkvm, which is only imported into the end user program crate.
//! In contrast, sp1-precompiles can be imported into any crate in the dependency tree.

pub mod bls12381;
pub mod bn254;
pub mod io;
pub mod secp256k1;
pub mod unconstrained;
pub mod utils;
#[cfg(feature = "verify")]
pub mod verify;

pub const BIGINT_WIDTH_WORDS: usize = 8;

extern "C" {
    pub fn syscall_halt(exit_code: u8) -> !;
    pub fn syscall_write(fd: u32, write_buf: *const u8, nbytes: usize);
    pub fn syscall_read(fd: u32, read_buf: *mut u8, nbytes: usize);
    pub fn syscall_sha256_extend(w: *mut u32);
    pub fn syscall_sha256_compress(w: *mut u32, state: *mut u32);
    pub fn syscall_ed_add(p: *mut u32, q: *mut u32);
    pub fn syscall_ed_decompress(point: &mut [u8; 64]);
    pub fn syscall_secp256k1_add(p: *mut u32, q: *const u32);
    pub fn syscall_secp256k1_double(p: *mut u32);
    pub fn syscall_secp256k1_decompress(point: &mut [u8; 64], is_odd: bool);
    pub fn syscall_bn254_add(p: *mut u32, q: *const u32);
    pub fn syscall_bn254_double(p: *mut u32);
    pub fn syscall_bls12381_add(p: *mut u32, q: *const u32);
    pub fn syscall_bls12381_double(p: *mut u32);
    pub fn syscall_keccak_permute(state: *mut u64);
    pub fn syscall_uint256_mulmod(x: *mut u32, y: *const u32);
    pub fn syscall_enter_unconstrained() -> bool;
    pub fn syscall_exit_unconstrained();
    pub fn syscall_verify_sp1_proof(vkey: &[u32; 8], pv_digest: &[u8; 32]);
    pub fn syscall_hint_len() -> usize;
    pub fn syscall_hint_read(ptr: *mut u8, len: usize);
    pub fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8;
    pub fn syscall_bls12381_decompress(point: &mut [u8; 96], is_odd: bool);
    pub fn sys_bigint(
        result: *mut [u32; BIGINT_WIDTH_WORDS],
        op: u32,
        x: *const [u32; BIGINT_WIDTH_WORDS],
        y: *const [u32; BIGINT_WIDTH_WORDS],
        modulus: *const [u32; BIGINT_WIDTH_WORDS],
    );
}
