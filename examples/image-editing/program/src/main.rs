//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let vec_1 = sp1_zkvm::io::read::<Vec<u128>>();
    let vec_2 = sp1_zkvm::io::read::<Vec<u128>>();
    let threshold = sp1_zkvm::io::read::<u128>();

    assert_eq!(vec_1.len(), vec_2.len(), "Vectors have different lengths");

    let sum_of_diffs_squared: u128 = vec_1
        .iter()
        .zip(vec_2.iter()) // Combine the two vectors
        .map(|(a, b)| (a - b).pow(2)) // Calculate the difference squared for each pair
        .sum();
    
    println!("================== program ====================");
    // let ret = sum_of_diffs_squared < threshold;
    sp1_zkvm::io::write(&sum_of_diffs_squared);
}
