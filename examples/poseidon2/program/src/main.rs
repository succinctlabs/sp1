#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::syscall_poseidon2;
use sp1_zkvm::syscalls::Poseidon2State;

pub fn main() {
    let p = Poseidon2State([0; 16]);
    syscall_poseidon2(&p);

    let p = Poseidon2State([1; 16]);
    syscall_poseidon2(&p);

    let p = Poseidon2State([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    syscall_poseidon2(&p);

    let p = Poseidon2State([0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0]);
    syscall_poseidon2(&p);

    let p = Poseidon2State([10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160]);
    for _ in 0..1000000 {
        syscall_poseidon2(&p);
    }

    println!("successfully evaluated poseidon2");
}
