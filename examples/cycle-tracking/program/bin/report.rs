#![no_main]
sp1_zkvm::entrypoint!(main);

#[sp1_derive::cycle_tracker]
pub fn expensive_function(x: usize) -> usize {
    let mut y = 1;
    for _ in 0..100 {
        y *= x;
        y %= 7919;
    }
    y
}

pub fn main() {
    let mut nums = vec![1, 1];

    // Setup a large vector with Fibonacci-esque numbers.
    println!("cycle-tracker-report-start: setup");
    for _ in 0..100 {
        let mut c = nums[nums.len() - 1] + nums[nums.len() - 2];
        c %= 7919;
        nums.push(c);
    }
    println!("cycle-tracker-report-end: setup");
}
