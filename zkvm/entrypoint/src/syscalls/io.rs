#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Reads data from the prover.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_read(fd: u32, read_buf: *mut u8, nbytes: usize) {
    let whole_words: usize = nbytes / 4;
    let remaining_bytes = nbytes % 4;

    for i in 0..whole_words {
        let offset = i * 4;
        #[cfg(target_os = "zkvm")]
        unsafe {
            let mut word;
            asm!(
                "ecall",
                in("t0") crate::syscalls::LWA,
                in("a0") fd,
                in("a1") 4, // The number of bytes we're requesting
                lateout("t0") word,
            );

            // Copy the word into the read buffer
            let word_ptr = &mut word as *mut u32 as *mut u8;
            for j in 0..4 {
                *read_buf.add(offset + j) = *word_ptr.add(j);
            }
        }
    }

    // Handle the remaining bytes for the last partial word
    if remaining_bytes > 0 {
        let offset = whole_words * 4;
        #[cfg(target_os = "zkvm")]
        unsafe {
            let mut word;
            asm!(
                "ecall",
                in("t0") crate::syscalls::LWA,
                in("a0") fd,
                in("a1") remaining_bytes, // Request the remaining bytes
                lateout("t0") word,
            );

            // Copy the necessary bytes of the word into the read buffer
            let word_ptr = &mut word as *mut u32 as *mut u8;
            for j in 0..remaining_bytes {
                *read_buf.add(offset + j) = *word_ptr.add(j);
            }
        }
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Write data to the prover.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_write(fd: u32, write_buf: *const u8, nbytes: usize) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::WRITE,
            in("a0") fd,
            in("a1") write_buf,
            in("a2") nbytes,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
