//! Raw `ecall` wrappers and SP1 syscall number re-exports.
//!
//! SP1's syscall ABI (see `crates/zkvm/entrypoint/src/syscalls/`) is:
//!
//! * `ecall` instruction with the syscall number in `t0`
//! * arguments in `a0`, `a1`, `a2`, ... (RISC-V calling convention)
//! * return value (when present) in `t0` (lateout) or via an `a0` out-pointer
//!
//! For halt / write / hint we delegate to `sp1-zkvm`'s high-level
//! `syscall_*` wrappers (which also feed the public-values hasher and
//! commit the digest before HALT). The `ecallN` helpers below are kept
//! for the placeholder precompile dispatches that don't yet have a
//! matching SP1 wrapper.

#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Issue an `ecall` with no arguments and no return value.
#[inline(always)]
#[cfg(target_os = "zkvm")]
pub unsafe fn ecall0(syscall: u32) {
    asm!("ecall", in("t0") syscall, options(nostack));
}

/// Issue an `ecall` with `a0`, `a1`.
#[inline(always)]
#[cfg(target_os = "zkvm")]
pub unsafe fn ecall2(syscall: u32, a0: usize, a1: usize) {
    asm!("ecall", in("t0") syscall, in("a0") a0, in("a1") a1, options(nostack));
}

/// Issue an `ecall` with `a0`, `a1`, `a2`.
#[inline(always)]
#[cfg(target_os = "zkvm")]
pub unsafe fn ecall3(syscall: u32, a0: usize, a1: usize, a2: usize) {
    asm!(
        "ecall",
        in("t0") syscall,
        in("a0") a0, in("a1") a1, in("a2") a2,
        options(nostack),
    );
}

/// Issue an `ecall` with `a0..a3`.
#[inline(always)]
#[cfg(target_os = "zkvm")]
pub unsafe fn ecall4(syscall: u32, a0: usize, a1: usize, a2: usize, a3: usize) {
    asm!(
        "ecall",
        in("t0") syscall,
        in("a0") a0, in("a1") a1, in("a2") a2, in("a3") a3,
        options(nostack),
    );
}

// Host-target stubs so cargo check / IDE tooling work outside the zkvm.
#[cfg(not(target_os = "zkvm"))]
pub unsafe fn ecall0(_syscall: u32) {
    unimplemented!("libzkevm ecalls only run on the SP1 zkVM target");
}
#[cfg(not(target_os = "zkvm"))]
pub unsafe fn ecall2(_syscall: u32, _a0: usize, _a1: usize) {
    unimplemented!("libzkevm ecalls only run on the SP1 zkVM target");
}
#[cfg(not(target_os = "zkvm"))]
pub unsafe fn ecall3(_syscall: u32, _a0: usize, _a1: usize, _a2: usize) {
    unimplemented!("libzkevm ecalls only run on the SP1 zkVM target");
}
#[cfg(not(target_os = "zkvm"))]
pub unsafe fn ecall4(_syscall: u32, _a0: usize, _a1: usize, _a2: usize, _a3: usize) {
    unimplemented!("libzkevm ecalls only run on the SP1 zkVM target");
}

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

/// Placeholder syscall numbers for accelerators not yet wired into SP1.
///
/// `0xDEAD_xxxx` is reserved for "the human still needs to pin/implement
/// this". `grep -r 0xDEAD_ libzkevm/src` finds them all. Each one
/// corresponds to one C accelerator function.
#[allow(dead_code)]
pub mod placeholder {
    // High-level / non-precompile
    pub const TODO_KECCAK256: u32 = 0xDEAD_0001;

    // Ethereum precompiles 0x01..0x11
    pub const TODO_ECRECOVER: u32 = 0xDEAD_0101;
    pub const TODO_SHA256: u32 = 0xDEAD_0102;
    pub const TODO_RIPEMD160: u32 = 0xDEAD_0103;
    pub const TODO_MODEXP: u32 = 0xDEAD_0105;
    pub const TODO_BN254_G1_ADD: u32 = 0xDEAD_0106;
    pub const TODO_BN254_G1_MUL: u32 = 0xDEAD_0107;
    pub const TODO_BN254_PAIRING: u32 = 0xDEAD_0108;
    pub const TODO_BLAKE2F: u32 = 0xDEAD_0109;
    pub const TODO_KZG_POINT_EVAL: u32 = 0xDEAD_010A;
    pub const TODO_BLS12_G1_ADD: u32 = 0xDEAD_010B;
    pub const TODO_BLS12_G1_MSM: u32 = 0xDEAD_010C;
    pub const TODO_BLS12_G2_ADD: u32 = 0xDEAD_010D;
    pub const TODO_BLS12_G2_MSM: u32 = 0xDEAD_010E;
    pub const TODO_BLS12_PAIRING: u32 = 0xDEAD_010F;
    pub const TODO_BLS12_MAP_FP_TO_G1: u32 = 0xDEAD_0110;
    pub const TODO_BLS12_MAP_FP2_TO_G2: u32 = 0xDEAD_0111;

    // Non-precompile verifier helpers
    pub const TODO_SECP256K1_VERIFY: u32 = 0xDEAD_0201;
    pub const TODO_SECP256R1_VERIFY: u32 = 0xDEAD_0202;
}
