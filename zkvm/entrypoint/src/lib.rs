pub mod heap;
pub mod syscalls;
pub mod io {
    pub use sp1_precompiles::io::*;
}
pub mod precompiles {
    pub use sp1_precompiles::*;
}

extern crate alloc;

#[macro_export]
macro_rules! entrypoint {
    ($path:path) => {
        const ZKVM_ENTRY: fn() = $path;

        use $crate::heap::SimpleAlloc;

        #[global_allocator]
        static HEAP: SimpleAlloc = SimpleAlloc;

        mod zkvm_generated_main {

            #[no_mangle]
            fn main() {
                super::ZKVM_ENTRY()
            }
        }
    };
}

#[cfg(all(target_os = "zkvm", feature = "libm"))]
mod libm;

#[cfg(target_os = "zkvm")]
mod zkvm {
    use crate::syscalls::syscall_halt;
    use getrandom::{register_custom_getrandom, Error};

    #[cfg(not(feature = "interface"))]
    #[no_mangle]
    unsafe extern "C" fn __start() {
        {
            extern "C" {
                fn main();
            }
            main()
        }

        syscall_halt();
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
        jal ra, __start;
    "#,
        sym STACK_TOP
    );

    static GETRANDOM_WARNING_ONCE: std::sync::Once = std::sync::Once::new();

    fn zkvm_getrandom(s: &mut [u8]) -> Result<(), Error> {
        use rand::Rng;
        use rand::SeedableRng;

        GETRANDOM_WARNING_ONCE.call_once(|| {
            println!("WARNING: Using insecure random number generator");
        });
        let mut rng = rand::rngs::StdRng::seed_from_u64(123);
        for i in 0..s.len() {
            s[i] = rng.gen();
        }
        Ok(())
    }

    register_custom_getrandom!(zkvm_getrandom);
}
