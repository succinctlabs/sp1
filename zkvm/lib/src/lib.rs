//! System calls for the SP1 zkVM.

#[cfg(feature = "bls12381")]
pub mod bls12381;
#[cfg(feature = "bn254")]
pub mod bn254;
pub mod io;
#[cfg(feature = "secp256k1")]
pub mod secp256k1;
pub mod unconstrained;
pub mod utils;
#[cfg(feature = "verify")]
pub mod verify;

extern "C" {
    /// Halts the program with the given exit code.
    pub fn syscall_halt(exit_code: u8) -> !;

    /// Writes the bytes in the given buffer to the given file descriptor.
    pub fn syscall_write(fd: u32, write_buf: *const u8, nbytes: usize);

    /// Reads the bytes from the given file descriptor into the given buffer.
    pub fn syscall_read(fd: u32, read_buf: *mut u8, nbytes: usize);

    /// Executes the SHA-256 extend operation on the given word array.
    pub fn syscall_sha256_extend(w: *mut u32);

    /// Executes the SHA-256 compress operation on the given word array and a given state.
    pub fn syscall_sha256_compress(w: *mut u32, state: *mut u32);

    /// Executes an Ed25519 curve addition on the given points.
    pub fn syscall_ed_add(p: *mut u32, q: *mut u32);

    /// Executes an Ed25519 curve decompression on the given point.
    pub fn syscall_ed_decompress(point: &mut [u8; 64]);

    /// Executes an Sepc256k1 curve addition on the given points.
    pub fn syscall_secp256k1_add(p: *mut u32, q: *const u32);

    /// Executes an Secp256k1 curve doubling on the given point.
    pub fn syscall_secp256k1_double(p: *mut u32);

    /// Executes an Secp256k1 curve decompression on the given point.
    pub fn syscall_secp256k1_decompress(point: &mut [u8; 64], is_odd: bool);

    /// Executes a Bn254 curve addition on the given points.
    pub fn syscall_bn254_add(p: *mut u32, q: *const u32);

    /// Executes a Bn254 curve doubling on the given point.
    pub fn syscall_bn254_double(p: *mut u32);

    /// Executes a BLS12-381 curve addition on the given points.
    pub fn syscall_bls12381_add(p: *mut u32, q: *const u32);

    /// Executes a BLS12-381 curve doubling on the given point.
    pub fn syscall_bls12381_double(p: *mut u32);

    /// Executes the Keccak-256 permutation on the given state.
    pub fn syscall_keccak_permute(state: *mut u64);

    /// Executes an uint256 multiplication on the given inputs.
    pub fn syscall_uint256_mulmod(x: *mut u32, y: *const u32);

    /// Enters unconstrained mode.
    pub fn syscall_enter_unconstrained() -> bool;

    /// Exits unconstrained mode.
    pub fn syscall_exit_unconstrained();

    /// Defers the verification of a valid SP1 zkVM proof.
    pub fn syscall_verify_sp1_proof(vkey: &[u32; 8], pv_digest: &[u8; 32]);

    /// Returns the length of the next element in the hint stream.
    pub fn syscall_hint_len() -> usize;

    /// Reads the next element in the hint stream into the given buffer.
    pub fn syscall_hint_read(ptr: *mut u8, len: usize);

    /// Allocates a buffer aligned to the given alignment.
    pub fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8;

    /// Decompresses a BLS12-381 point.
    pub fn syscall_bls12381_decompress(point: &mut [u8; 96], is_odd: bool);

    /// Computes a big integer operation with a modulus.
    pub fn sys_bigint(
        result: *mut [u32; 8],
        op: u32,
        x: *const [u32; 8],
        y: *const [u32; 8],
        modulus: *const [u32; 8],
    );
    /// Computes a 384-bit integer operation with a modulus on the BLS12-381 curve.
    pub fn bls12381_sys_bigint(
        result: *mut [u32; 12],
        op: u32,
        x: *const [u32; 12],
        y: *const [u32; 12],
    );
}
