#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the Keccak256 permutation on the given state.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_keccak_permute(state: *mut u64) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::KECCAK_PERMUTE,
            in("a0") state,
            in("a1") 0
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
