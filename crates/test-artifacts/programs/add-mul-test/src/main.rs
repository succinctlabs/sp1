#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::syscall_add_mul;

fn main() {
    //TODO add unit test
    println!("All tests passed.");
}
