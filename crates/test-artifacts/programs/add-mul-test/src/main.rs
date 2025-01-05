#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::syscall_add_mul;

fn main() {
    //TODO add unit test
    let mut a: u32 = 1;
    let b: u32 = 2;
    let c: u32 = 4;
    let d: u32 = 5;
    println!("a: {}", a);
    syscall_add_mul(
        &mut a,
        &b,
        &c,
        &d
    );
    let result_syscall = a;
    let result = 22;
    println!("result_syscall: {}", result_syscall);
    assert_eq!(result_syscall, result);

    println!("All tests passed.");
}
