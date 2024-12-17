use super::io::StdinBuffer;

pub struct UnconstrainedBlock {
    pub stdin_buffer: StdinBuffer,
    // other fields, if any...
}

impl UnconstrainedBlock {
    pub fn new() -> Self {
        Self {
            stdin_buffer: StdinBuffer::new(),
            // initialization of other fields...
        }
    }

    pub fn write_front(&mut self, data: Vec<u8>) {
        self.stdin_buffer.write_front(data);
    }
}
