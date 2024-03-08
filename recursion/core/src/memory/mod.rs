use crate::air::Word;
use sp1_derive::AlignedBorrow;
use std::mem::size_of;

#[derive(Debug, Clone)]
pub struct MemoryRecord<F> {
    pub value: F,
    pub timestamp: F,
    pub prev_value: F,
    pub prev_timestamp: F,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
pub struct MemoryReadCols<T> {
    pub value: Word<T>,
    pub prev_timestamp: T,
    pub curr_timestamp: T,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
pub struct MemoryWriteCols<T> {
    pub prev_value: Word<T>,
    pub curr_value: Word<T>,
    pub prev_timestamp: T,
    pub curr_timestamp: T,
}
