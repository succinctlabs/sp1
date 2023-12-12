const ADDR_LEN: usize = 4;

/// An AIR representation of a memory address in the instruction set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Address<T>(pub [T; ADDR_LEN]);
