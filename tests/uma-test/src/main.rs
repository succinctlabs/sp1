#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::sys_uma;

pub fn main() {
    let mut state = [0u32; 8];
    let mut w = [0u32; 64];

    sys_uma(state.as_mut_ptr(), w.as_mut_ptr());

    println!("{:?}", state);
}
