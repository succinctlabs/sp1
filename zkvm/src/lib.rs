#[cfg(target_os = "zkvm")]
use syscall::syscall_halt;

#[cfg(target_os = "zkvm")]
use getrandom::{register_custom_getrandom, Error};

use core::alloc::{GlobalAlloc, Layout};

extern crate alloc;

pub mod io;
pub mod memory;
pub mod syscall;

pub use io::*;

pub const WORD_SIZE: usize = 4;

#[macro_export]
macro_rules! entrypoint {
    ($path:path) => {
        const ZKVM_ENTRY: fn() = $path;

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

    syscall_halt();
}

#[cfg(target_os = "zkvm")]
static STACK_TOP: u32 = 0x0020_0400; // TODO: put in whatever.

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

/// RUNTIME

struct SimpleAlloc;

unsafe impl GlobalAlloc for SimpleAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        memory::sys_alloc_aligned(layout.size(), layout.align())
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

// TODO: should we use this even outside of vm?
#[cfg(all(target_os = "zkvm", not(feature = "no-entrypoint")))]
#[global_allocator]
static HEAP: SimpleAlloc = SimpleAlloc;

#[cfg(target_os = "zkvm")]
static GETRANDOM_WARNING_ONCE: std::sync::Once = std::sync::Once::new();

#[cfg(target_os = "zkvm")]
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

#[cfg(target_os = "zkvm")]
register_custom_getrandom!(zkvm_getrandom);
