#[cfg(target_os = "zkvm")]
use core::arch::asm;

#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_sha256_compress(w: *mut u32, state: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        let mut w_and_h = [0u32; 72];
        let w_slice = std::slice::from_raw_parts_mut(w, 64);
        let h_slice = std::slice::from_raw_parts_mut(state, 8);
        w_and_h[0..64].copy_from_slice(w_slice);
        w_and_h[64..72].copy_from_slice(h_slice);
        asm!(
            "ecall",
            in("t0") crate::syscalls::SHA_COMPRESS,
            in("a0") w_and_h.as_ptr()
        );
        for i in 0..64 {
            *w.add(i) = w_and_h[i];
        }
        for i in 0..8 {
            *state.add(i) = w_and_h[64 + i];
        }
    }
}
