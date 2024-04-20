#![allow(clippy::needless_range_loop)]

use crate::poseidon2::external::WIDTH;
mod external;

pub use external::Poseidon2Chip;

#[derive(Debug, Clone)]
pub struct Poseidon2Event<F> {
    pub input: [F; WIDTH],
}
