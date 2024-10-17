extern crate alloc;

pub mod heap;
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

    pub static mut PUBLIC_VALUES_HASHER: Option<Sha256> = None;

    #[no_mangle]
    unsafe extern "C" fn __start() {
        {
            PUBLIC_VALUES_HASHER = Some(Sha256::new());
            #[cfg(feature = "verify")]
            {
                DEFERRED_PROOFS_DIGEST = Some([BabyBear::zero(); 8]);
            }

            extern "C" {
                fn main();
            }
            main()
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

    pub fn zkvm_getrandom(s: &mut [u8]) -> Result<(), getrandom::Error> {
        unsafe {
            crate::syscalls::sys_rand(s.as_mut_ptr(), s.len());
        }

        Ok(())
    }

    getrandom::register_custom_getrandom!(zkvm_getrandom);
}

#[macro_export]
macro_rules! entrypoint {
    ($path:path) => {
        #[cfg(target_os = "zkvm")]
        mod zkvm_generated_main {
            use $crate::heap::SimpleAlloc;

            #[global_allocator]
            static HEAP: SimpleAlloc = SimpleAlloc;

            #[no_mangle]
            fn main() {
                // Link to the actual entrypoint only when compiling for zkVM. Doing this avoids
                // compilation errors when building for the host target.
                //
                // Note that, however, it's generally considered wasted effort compiling zkVM
                // programs against the host target. This just makes it such that doing so wouldn't
                // result in an error, which can happen when building a Cargo workspace containing
                // zkVM program crates.
                $path()
            }
        }

        /// If we compile the entrypoint for the host target, we need to provide a dummy `main`
        /// so the test harness doesnt get confused.
        ///
        /// Returning `()` is not sufficient, as the test harness expects a `i32` return value.
        ///
        /// Also a #[no_mangle] main function must be present otherwise rustc will fail.
        /// see: https://github.com/rust-lang/rust/issues/59162
        #[cfg(not(target_os = "zkvm"))]
        mod not_zkvm {
            #[no_mangle]
            fn main() -> i32 {
                0
            }
        }
    };
}
