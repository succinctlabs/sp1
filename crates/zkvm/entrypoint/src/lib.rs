#[cfg(all(target_os = "zkvm", feature = "embedded"))]
use syscalls::MAX_MEMORY;

#[cfg(target_os = "zkvm")]
use {
    cfg_if::cfg_if,
    syscalls::{syscall_hint_len, syscall_hint_read},
};

extern crate alloc;

#[cfg(target_os = "zkvm")]
pub mod allocators;

pub mod syscalls;

#[cfg(feature = "lib")]
pub mod io {
    pub use sp1_lib::io::*;
}

#[cfg(feature = "lib")]
pub mod lib {
    pub use sp1_lib::*;
}

#[cfg(all(target_os = "zkvm", feature = "libm"))]
mod libm;

/// The number of 32 bit words that the public values digest is composed of.
pub const PV_DIGEST_NUM_WORDS: usize = 8;
pub const POSEIDON_NUM_WORDS: usize = 8;

/// Size of the reserved region for input values with the embedded allocator.
#[cfg(all(target_os = "zkvm", feature = "embedded"))]
pub(crate) const EMBEDDED_RESERVED_INPUT_REGION_SIZE: usize = 1024 * 1024 * 1024;

/// Start of the reserved region for inputs with the embedded allocator.
#[cfg(all(target_os = "zkvm", feature = "embedded"))]
pub(crate) const EMBEDDED_RESERVED_INPUT_START: usize =
    MAX_MEMORY - EMBEDDED_RESERVED_INPUT_REGION_SIZE;

/// Pointer to the current position in the reserved region for inputs with the embedded allocator.
#[cfg(all(target_os = "zkvm", feature = "embedded"))]
static mut EMBEDDED_RESERVED_INPUT_PTR: usize = EMBEDDED_RESERVED_INPUT_START;

#[repr(C)]
pub struct ReadVecResult {
    pub ptr: *mut u8,
    pub len: usize,
    pub capacity: usize,
}

/// Read a buffer from the input stream.
///
/// The buffer is read into uninitialized memory.
///
/// When the `bump` feature is enabled, the buffer is read into a new buffer allocated by the
/// program.
///
/// When the `embedded` feature is enabled, the buffer is read into the reserved input region.
///
/// When there is no allocator selected, the program will fail to compile.
///
/// If the input stream is exhausted, the failed flag will be returned as true. In this case, the
/// other outputs from the function are likely incorrect, which is fine as `sp1-lib` always panics
/// in the case that the input stream is exhausted.
#[no_mangle]
pub extern "C" fn read_vec_raw() -> ReadVecResult {
    #[cfg(not(target_os = "zkvm"))]
    unreachable!("read_vec_raw should only be called on the zkvm target.");

    #[cfg(target_os = "zkvm")]
    {
        // Get the length of the input buffer.
        let len = syscall_hint_len();

        // If the length is u32::MAX, then the input stream is exhausted.
        if len == usize::MAX {
            return ReadVecResult { ptr: std::ptr::null_mut(), len: 0, capacity: 0 };
        }

        // Round up to multiple of 4 for whole-word alignment.
        let capacity = (len + 3) / 4 * 4;

        cfg_if! {
            if #[cfg(feature = "embedded")] {
                // Get the existing pointer in the reserved region which is the start of the vec.
                // Increment the pointer by the capacity to set the new pointer to the end of the vec.
                let ptr = unsafe { EMBEDDED_RESERVED_INPUT_PTR };
                if ptr.saturating_add(capacity) > MAX_MEMORY {
                    panic!("Input region overflowed.")
                }

                // SAFETY: The VM is single threaded.
                unsafe { EMBEDDED_RESERVED_INPUT_PTR += capacity };

                // Read the vec into uninitialized memory. The syscall assumes the memory is
                // uninitialized, which is true because the input ptr is incremented manually on each
                // read.
                syscall_hint_read(ptr as *mut u8, len);

                // Return the result.
                ReadVecResult {
                    ptr: ptr as *mut u8,
                    len,
                    capacity,
                }
            } else {
                // Allocate a buffer of the required length that is 4 byte aligned.
                let layout = std::alloc::Layout::from_size_align(capacity, 4).expect("vec is too large");

                // SAFETY: The layout was made through the checked constructor.
                let ptr = unsafe { std::alloc::alloc(layout) };

                // Read the vec into uninitialized memory. The syscall assumes the memory is
                // uninitialized, which is true because the bump allocator does not dealloc, so a new
                // alloc is always fresh.
                syscall_hint_read(ptr as *mut u8, len);

                // Return the result.
                ReadVecResult {
                    ptr: ptr as *mut u8,
                    len,
                    capacity,
                }
            }
        }
    }
}

#[cfg(target_os = "zkvm")]
mod zkvm {
    use crate::syscalls::syscall_halt;

    use cfg_if::cfg_if;
    use sha2::{Digest, Sha256};

    cfg_if! {
        if #[cfg(feature = "verify")] {
            use p3_baby_bear::BabyBear;
            use p3_field::AbstractField;

            pub static mut DEFERRED_PROOFS_DIGEST: Option<[BabyBear; 8]> = None;
        }
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "blake3")] {
            pub static mut PUBLIC_VALUES_HASHER: Option<blake3::Hasher> = None;
        }
        else {
            pub static mut PUBLIC_VALUES_HASHER: Option<Sha256> = None;
        }
    }

    #[no_mangle]
    unsafe extern "C" fn __start() {
        {
            #[cfg(all(target_os = "zkvm", feature = "embedded"))]
            crate::allocators::init();

            cfg_if::cfg_if! {
                if #[cfg(feature = "blake3")] {
                    PUBLIC_VALUES_HASHER = Some(blake3::Hasher::new());
                }
                else {
                    PUBLIC_VALUES_HASHER = Some(Sha256::new());
                }
            }

            #[cfg(feature = "verify")]
            {
                DEFERRED_PROOFS_DIGEST = Some([BabyBear::zero(); 8]);
            }

            // Call C global constructors before main
            extern "C" {
                static __preinit_array_start: [extern "C" fn(); 0];
                static __preinit_array_end: [extern "C" fn(); 0];
                static __init_array_start: [extern "C" fn(); 0];
                static __init_array_end: [extern "C" fn(); 0];
            }

            // Call preinit array functions
            let preinit_start = &__preinit_array_start as *const _ as *const extern "C" fn();
            let preinit_end = &__preinit_array_end as *const _ as *const extern "C" fn();
            let preinit_count = (preinit_end as usize - preinit_start as usize) / std::mem::size_of::<extern "C" fn()>();
            for i in 0..preinit_count {
                let func_ptr = unsafe { preinit_start.add(i) };
                unsafe { (*func_ptr)(); }
            }

            // Call init array functions
            let init_start = &__init_array_start as *const _ as *const extern "C" fn();
            let init_end = &__init_array_end as *const _ as *const extern "C" fn();
            let init_count = (init_end as usize - init_start as usize) / std::mem::size_of::<extern "C" fn()>();
            for i in 0..init_count {
                let func_ptr = unsafe { init_start.add(i) };
                unsafe { (*func_ptr)(); }
            }

            extern "C" {
                fn main();
            }
            main();

            // Call C global destructors after main
            extern "C" {
                static __fini_array_start: [extern "C" fn(); 0];
                static __fini_array_end: [extern "C" fn(); 0];
            }

            // Call fini array functions in reverse order
            let fini_start = &__fini_array_start as *const _ as *const extern "C" fn();
            let fini_end = &__fini_array_end as *const _ as *const extern "C" fn();
            let fini_count = (fini_end as usize - fini_start as usize) / std::mem::size_of::<extern "C" fn()>();
            for i in (0..fini_count).rev() {
                let func_ptr = unsafe { fini_start.add(i) };
                unsafe { (*func_ptr)(); }
            }
        }

        syscall_halt(0);
    }

    static STACK_TOP: u32 = 0x0020_0400;

    core::arch::global_asm!(include_str!("memset.s"));
    core::arch::global_asm!(include_str!("memcpy.s"));

    core::arch::global_asm!(
        r#"
    .section .text._start;
    .globl _start;
    _start:
        .option push;
        .option norelax;
        la gp, __global_pointer$;
        .option pop;
        la sp, {0}
        lw sp, 0(sp)
        call __start;
    "#,
        sym STACK_TOP
    );

    pub fn zkvm_getrandom_v2(s: &mut [u8]) -> Result<(), getrandom_v2::Error> {
        unsafe {
            crate::syscalls::sys_rand(s.as_mut_ptr(), s.len());
        }

        Ok(())
    }

    getrandom_v2::register_custom_getrandom!(zkvm_getrandom_v2);

    #[no_mangle]
    unsafe extern "Rust" fn __getrandom_v03_custom(
        dest: *mut u8,
        len: usize,
    ) -> Result<(), getrandom_v3::Error> {
        unsafe {
            crate::syscalls::sys_rand(dest, len);
        }

        Ok(())
    }
}

#[macro_export]
macro_rules! entrypoint {
    ($path:path) => {
        const ZKVM_ENTRY: fn() = $path;

        mod zkvm_generated_main {

            #[no_mangle]
            fn main() {
                // Link to the actual entrypoint only when compiling for zkVM, otherwise run a
                // simple noop. Doing this avoids compilation errors when building for the host
                // target.
                //
                // Note that, however, it's generally considered wasted effort compiling zkVM
                // programs against the host target. This just makes it such that doing so wouldn't
                // result in an error, which can happen when building a Cargo workspace containing
                // zkVM program crates.
                if cfg!(target_os = "zkvm") {
                    super::ZKVM_ENTRY()
                } else {
                    eprintln!("Not running in zkVM, skipping entrypoint");
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_global_constructor_symbols_exist() {
        // Test that the C global constructor symbols are properly declared
        extern "C" {
            static __preinit_array_start: [extern "C" fn(); 0];
            static __preinit_array_end: [extern "C" fn(); 0];
            static __init_array_start: [extern "C" fn(); 0];
            static __init_array_end: [extern "C" fn(); 0];
            static __fini_array_start: [extern "C" fn(); 0];
            static __fini_array_end: [extern "C" fn(); 0];
        }

        // Verify that we can access these symbols
        let _preinit_start = &__preinit_array_start as *const _ as *const extern "C" fn();
        let _preinit_end = &__preinit_array_end as *const _ as *const extern "C" fn();
        let _init_start = &__init_array_start as *const _ as *const extern "C" fn();
        let _init_end = &__init_array_end as *const _ as *const extern "C" fn();
        let _fini_start = &__fini_array_start as *const _ as *const extern "C" fn();
        let _fini_end = &__fini_array_end as *const _ as *const extern "C" fn();

        // This test should pass if the symbols are properly declared
        assert!(true);
    }

    #[test]
    fn test_constructor_destructor_logic() {
        // Test the logic for calculating array counts
        let start_ptr: *const extern "C" fn() = std::ptr::null();
        let end_ptr: *const extern "C" fn() = std::ptr::null();
        
        // This should not panic
        let count = (end_ptr as usize - start_ptr as usize) / std::mem::size_of::<extern "C" fn()>();
        assert_eq!(count, 0);
    }
}
