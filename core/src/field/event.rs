#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldEvent {
    pub ltu: bool,
    pub b: u32,
    pub c: u32,
}

impl FieldEvent {
    pub const fn new(ltu: bool, b: u32, c: u32) -> Self {
        Self { ltu, b, c }
    }
}
