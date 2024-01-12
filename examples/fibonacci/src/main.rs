#![no_main]

extern crate curta_zkvm;
use curta_zkvm::syscall::syscall_halt;

#[cfg(target_os = "zkvm")]
use core::arch::asm;

curta_zkvm::entry!(main);

pub fn main() {
    let mut nums = vec![1, 1];

    for _ in 0..25 {
        let c = nums[nums.len() - 1] + nums[nums.len() - 2];
        nums.push(c);
    }

    let result = nums[nums.len() - 1];

    #[cfg(not(target_os = "zkvm"))]
    println!("result: {}", result);

    // #[cfg(target_os = "zkvm")]
    // unsafe {
    //     asm!(
    //         "ecall",
    //         in("t0") result,
    //     );
    // }

    syscall_halt();
}
