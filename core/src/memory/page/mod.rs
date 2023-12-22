mod air;

pub const PAGE_DEGREE: usize = 10;
pub const PAGE_SIZE: usize = 1 << PAGE_DEGREE;

#[derive(Debug, Clone, Copy)]
pub struct InputPage {
    page_id: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct OutputPage {
    page_id: u16,
}
