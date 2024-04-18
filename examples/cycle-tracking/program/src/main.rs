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
    println!("cycle-tracker-start: setup");
    for _ in 0..100 {
        let mut c = nums[nums.len() - 1] + nums[nums.len() - 2];
        c %= 7919;
        nums.push(c);
    }
    println!("cycle-tracker-end: setup");

    println!("cycle-tracker-start: main-body");
    for i in 0..2 {
        let result = expensive_function(nums[nums.len() - i - 1]);
        println!("result: {}", result);
    }
    println!("cycle-tracker-end: main-body");
}
