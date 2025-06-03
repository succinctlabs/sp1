mod air;
pub mod columns;
mod trace;

#[derive(Default)]
pub struct Blake2fCompressChip;

impl Blake2fCompressChip {
    pub const fn new() -> Self {
        Self {}
    }
}