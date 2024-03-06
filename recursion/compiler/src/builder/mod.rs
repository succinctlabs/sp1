use crate::ir::Address;

pub trait Builder {
    /// An allocation of aligned memory with `size`.
    fn alloc(&mut self, size: usize) -> Address;
}

pub struct AsmBuilder {
    ap: usize,
}

impl Builder for AsmBuilder {
    fn alloc(&mut self, size: usize) -> Address {
        let reminder = self.ap % size;
        if reminder != 0 {
            self.ap += size - reminder;
        }
        let ap = self.ap;
        self.ap += size;
        Address::Main(ap as u32)
    }
}
