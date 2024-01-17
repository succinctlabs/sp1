#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldLookupEvent {
    pub a: u8,
    pub b: u8,
    pub c: u8,
}

impl FieldLookupEvent {
    pub const fn new(a: u8, b: u8, c: u8) -> Self {
        Self { a, b, c }
    }
}
