use super::Store;

/// A simple store representing a function with no internal state and no co-processors.
pub struct BaseStore {
    pub clk: u32,
    pub fp: u32,
    pub pc: u32,
    pub memory: Vec<u8>,
}

impl Store for BaseStore {
    fn memory(&mut self) -> &mut [u8] {
        &mut self.memory
    }

    fn clk(&mut self) -> &mut u32 {
        &mut self.clk
    }

    fn fp(&mut self) -> &mut u32 {
        &mut self.fp
    }

    fn pc(&mut self) -> &mut u32 {
        &mut self.pc
    }
}
