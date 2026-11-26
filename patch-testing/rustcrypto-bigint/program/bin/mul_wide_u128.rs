#![no_main]
sp1_zkvm::entrypoint!(main);

use crypto_bigint::{succinct::mul_wide_u128, U128};

pub fn main() {
    let (a, b): (u128, u128) = sp1_zkvm::io::read();
    let product = mul_wide_u128(&U128::from_u128(a), &U128::from_u128(b));
    sp1_zkvm::io::commit(product.as_words());
}
