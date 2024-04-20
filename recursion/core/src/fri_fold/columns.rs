use sp1_derive::AlignedBorrow;

use super::FriFoldEvent;

#[derive(AlignedBorrow, Debug, Clone)]
#[repr(C)]
pub struct FriFoldCols<T> {
    pub dummy: [T; 134],
    pub is_real: T,
}

impl<T: Clone> FriFoldCols<T> {
    pub fn populate(&mut self, event: &FriFoldEvent) {}
}
