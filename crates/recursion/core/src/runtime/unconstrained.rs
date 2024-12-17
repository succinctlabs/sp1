impl UnconstrainedBlock {
    // Adding a new method to write to the front of the queue
    pub fn write_front(&mut self, data: Vec<u8>) {
        self.stdin_buffer.write_front(data);
    }
}
