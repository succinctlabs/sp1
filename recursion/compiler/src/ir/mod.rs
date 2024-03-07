pub enum Address {
    Main(u32),
}

pub struct F(Address);

pub struct EF(Address);

pub trait Variable {
    fn size_of() -> usize;

    fn from_address(address: Address) -> Self;
}

impl Variable for F {
    fn size_of() -> usize {
        1
    }

    fn from_address(address: Address) -> Self {
        F(address)
    }
}

impl Variable for EF {
    fn size_of() -> usize {
        4
    }

    fn from_address(address: Address) -> Self {
        EF(address)
    }
}
