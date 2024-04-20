use sp1_derive::AlignedBorrow;

use super::AluEvent;
use crate::air::Block;

#[derive(AlignedBorrow, Default, Debug, Clone)]
#[repr(C)]
pub struct AluCols<T> {
    pub dummy: [T; 30],
    pub is_real: T,
}

impl<T: Clone> AluCols<T> {
    pub fn populate(&mut self, event: &AluEvent<T>) {}
}
