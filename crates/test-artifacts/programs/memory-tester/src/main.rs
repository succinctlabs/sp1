#![no_main]
sp1_zkvm::entrypoint!(main);

fn main() {
    let command = sp1_zkvm::io::read::<u8>();

    match command {
        0 => {
            // Trigger out-of-bound-write
            let ptr = ((1usize << (sp1_primitives::consts::MAX_JIT_LOG_ADDR + 3)) + 4) as *mut u32;
            unsafe { std::ptr::write_volatile(ptr, 42) };
        }
        1 => {
            // Repeated write every page of memory, hoping to trigger
            // OOM error.
            let mut ptr = ((1usize << sp1_primitives::consts::MAX_JIT_LOG_ADDR) - 256) as *mut u64;
            loop {
                unsafe { std::ptr::write_volatile(ptr, 17) };
                ptr = unsafe { ptr.sub(sp1_primitives::consts::PAGE_SIZE / 8) };
            }
        }
        _ => (),
    }
}
