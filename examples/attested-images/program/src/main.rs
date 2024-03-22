//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let len = sp1_zkvm::io::read::<u8>();

    let mut vec1 = Vec::new();
    for _i in 0..len {
        let pixel = sp1_zkvm::io::read::<u8>();
        vec1.push(pixel)
    }

    let mut vec2 = Vec::new();
    for _i in 0..len {
        let pixel = sp1_zkvm::io::read::<u8>();
        vec2.push(pixel)
    }

    let sum_of_diffs_squared: u8 = vec1
        .iter()
        .zip(vec2.iter()) // Combine the two vectors
        .map(|(a, b)| (a - b).pow(2)) // Calculate the difference squared for each pair
        .sum();

    sp1_zkvm::io::write(&sum_of_diffs_squared);
  
}
