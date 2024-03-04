#![no_main]
sp1_zkvm::entrypoint!(main);

extern "C" {
    fn syscall_simple_precompile(p: *mut u32);
}

pub fn main() {
    let mut p: [u32; 8] = [0u32, 1u32, 2u32, 3u32, 4u32, 5u32, 6u32, 7u32];
    println!("p: {:?}", p);

    unsafe {
        syscall_simple_precompile(p.as_mut_ptr() as *mut u32);
    }

    println!("p after calling syscall: {:?}", p);
    println!("done");
}
