mod columns;
mod compress_inner;
mod mix;
mod round;

#[cfg(test)]
pub mod compress_tests {
    use crate::precompiles::blake3::compress::columns::NUM_BLAKE3_EXTERNAL_COLS;

    pub fn test() {
        println!("NUM_BLAKE3_EXTERNAL_COLS = {}", NUM_BLAKE3_EXTERNAL_COLS);
    }
}
