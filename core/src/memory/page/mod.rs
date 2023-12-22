mod air;

pub const PAGE_DEGREE: usize = 10;
pub const PAGE_SIZE: usize = 1 << PAGE_DEGREE;

#[derive(Debug, Clone, Copy)]
pub enum PageChip {
    Input(u16),
    Output(u16),
}
