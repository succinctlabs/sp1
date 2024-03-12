use sp1_core::air::BinomialExtension;

use super::Block;

pub trait BinomialExtensionUtils<T> {
    fn from_block(block: Block<T>) -> Self;

    fn as_block(&self) -> Block<T>;
}

impl<T: Clone> BinomialExtensionUtils<T> for BinomialExtension<T> {
    fn from_block(block: Block<T>) -> Self {
        Self(block.0)
    }

    fn as_block(&self) -> Block<T> {
        Block(self.0.clone())
    }
}
