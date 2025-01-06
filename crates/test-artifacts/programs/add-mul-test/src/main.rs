#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::syscall_add_mul;

fn main() {
    //TODO add unit test
    let a: u32 = 1;
    let b: u32 = 2;
    let c: u32 = 4;
    let d: u32 = 5;
    let mut e: u32 = 0;
    println!("a: {}", a);
    syscall_add_mul(
        &a,
        &b,
        &c,
        &d,
        &mut e,
    );
    let result_syscall = e;
    let result = 22;
    println!("result_syscall: {}", result_syscall);
    assert_eq!(result_syscall, result);

    println!("All tests passed.");
}
