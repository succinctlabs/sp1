use super::{event::BaseEvent, Store};

/// A simple store representing a function with no internal state and no co-processors.
pub struct FunctionStore {
    pub clk: u32,
    pub fp: u32,
    pub pc: u32,
    pub memory: Vec<u8>,
    pub inputs: Vec<u32>,
    pub outputs: Vec<u32>,
}

impl Store for FunctionStore {
    type Event = BaseEvent;
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

impl FunctionStore {
    pub fn new(inputs: Vec<u32>) -> Self {
        Self {
            clk: 0,
            fp: 0,
            pc: 0,
            memory: vec![],
            inputs,
            outputs: vec![],
        }
    }
}
