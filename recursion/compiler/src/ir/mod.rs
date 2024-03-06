pub enum Address {
    Main(u32),
}

pub struct F(Address);

pub struct EF(Address);

pub trait Variable {
    fn size_of() -> usize;
}

impl Variable for F {
    fn size_of() -> usize {
        1
    }
}

impl Variable for EF {
    fn size_of() -> usize {
        4
    }
}
