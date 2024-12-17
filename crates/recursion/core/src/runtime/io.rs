use std::collections::VecDeque;

pub struct StdinBuffer {
    buffer: VecDeque<Vec<u8>>,
}

impl StdinBuffer {
    pub fn new() -> Self {
        Self {
            buffer: VecDeque::new(),
        }
    }

    pub fn write_front(&mut self, data: Vec<u8>) {
        self.buffer.push_front(data);
    }

    pub fn write(&mut self, data: Vec<u8>) {
        self.buffer.push_back(data);
    }

    pub fn read(&mut self) -> Option<Vec<u8>> {
        self.buffer.pop_front()
    }
}
