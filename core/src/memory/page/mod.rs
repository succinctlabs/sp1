mod air;
mod trace;

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

impl InputPage {
    pub fn new(page_id: u16) -> Self {
        Self { page_id }
    }

    pub fn page_id(&self) -> u16 {
        self.page_id
    }
}

impl OutputPage {
    pub fn new(page_id: u16) -> Self {
        Self { page_id }
    }

    pub fn page_id(&self) -> u16 {
        self.page_id
    }
}
