#[cfg(target_os = "zkvm")]
use core::arch::asm;

pub use crate::entrypoint;

#[macro_export]
macro_rules! entrypoint {
    ($path:path) => {
        // Type check the given path
        const ZKVM_ENTRY: fn() = $path;

        // Include generated main in a module so we don't conflict
        // with any other definitions of "main" in this file.
        mod zkvm_generated_main {
            #[no_mangle]
            fn main() {
                super::ZKVM_ENTRY()
            }
        }
    };
}

#[cfg(target_os = "zkvm")]
#[no_mangle]
unsafe extern "C" fn __start() {
    {
        extern "C" {
            fn main();
        }
        main()
    }
}

#[cfg(target_os = "zkvm")]
static STACK_TOP: u32 = 0x8000_0000; // TODO: put in whatever.

#[cfg(target_os = "zkvm")]
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
