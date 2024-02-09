pub mod heap;
pub mod precompiles;
pub mod syscalls;

pub use precompiles::io;

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

#[cfg(target_os = "zkvm")]
mod zkvm {
    use crate::syscalls::syscall_halt;
    use getrandom::{register_custom_getrandom, Error};

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

#[cfg(target_os = "zkvm")]
pub use zkvm::*;
