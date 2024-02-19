#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Fri fold operation.
///
/// The result is written to the addresses in the output mem entries.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_fri_fold(input_mem_ptr: *const u32, output_mem_ptr: *const *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::FRI_FOLD,
            in("a0") input_mem_ptr,
            in("a1") output_mem_ptr
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
