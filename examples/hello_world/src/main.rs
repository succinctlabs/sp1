#![no_main]

extern crate curta_zkvm;
use curta_zkvm::syscall::syscall_halt;

curta_zkvm::entry!(main);

pub fn main() {
    let mut a = 1;
    let mut b = 1;

    for _ in 0..100 {
        let c = a + b;
        a = b;
        b = c;
    }

    syscall_halt();
}
