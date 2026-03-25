#[cfg(target_os = "zkvm")]
use core::arch::asm;

pub use sp1_lib::poseidon2::{Poseidon2ByteHash, Poseidon2State};

/// Poseidon2 hash function syscall for the SP1 RISC-V zkVM.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_poseidon2(inout: &mut Poseidon2State) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::POSEIDON2,
            in("a0") inout.as_mut_ptr(),
            in("a1") 0,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
