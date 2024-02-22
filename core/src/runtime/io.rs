use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::Read;

use super::Runtime;

impl Read for Runtime {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_stdout_slice(buf);
        Ok(buf.len())
    }
}

impl Runtime {
    pub fn write_stdin<T: Serialize>(&mut self, input: &T) {
        let mut buf = Vec::new();
        bincode::serialize_into(&mut buf, input).expect("serialization failed");
        self.state.input_stream.extend(buf);
    }

    pub fn write_stdin_slice(&mut self, input: &[u8]) {
        self.state.input_stream.extend(input);
    }

    pub fn write_magic<T: Copy>(&mut self, input: T) {
        let ptr = self.state.magic_input_ptr;
        let len = std::mem::size_of::<T>();
        let slice = unsafe { std::slice::from_raw_parts(&input as *const T as *const u8, len) };
        println!("write_magic: ptr: {}, len: {}, data: {:?}", ptr, len, slice);
        // Write slice to memory, 4 bytes at a time (words)
        for i in 0..len / 4 {
            let word = u32::from_le_bytes([
                slice[i * 4],
                slice[i * 4 + 1],
                slice[i * 4 + 2],
                slice[i * 4 + 3],
            ]);
            // self.state.memory[&(ptr + (i as u32) * 4)] = (word, 0, 0);
            self.state.memory.insert(ptr + (i as u32) * 4, (word, 0, 0));
        }
        let last_byte_ptr = ptr + len as u32 / 4 * 4;
        if len % 4 != 0 {
            let mut word = 0;
            for i in 0..len % 4 {
                word |= (slice[(len / 4) * 4 + i] as u32) << (i * 8);
            }
            // self.state.memory[&(ptr + len as u32 / 4 * 4)] = (word, 0, 0);
            self.state.memory.insert(last_byte_ptr, (word, 0, 0));
        }
        self.state.magic_input_ptr = last_byte_ptr + 4;
        self.state.magic_input_ptrs.push((ptr, len));
    }

    pub fn read_stdout<T: DeserializeOwned>(&mut self) -> T {
        let result = bincode::deserialize_from::<_, T>(self);
        result.unwrap()
    }

    pub fn read_stdout_slice(&mut self, buf: &mut [u8]) {
        let len = buf.len();
        let start = self.state.output_stream_ptr;
        let end = start + len;
        assert!(end <= self.state.output_stream.len());
        buf.copy_from_slice(&self.state.output_stream[start..end]);
        self.state.output_stream_ptr = end;
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::runtime::Program;
    use crate::utils::tests::IO_ELF;
    use crate::utils::{self, prove_core, BabyBearBlake3};
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct MyPointUnaligned {
        pub x: usize,
        pub y: usize,
        pub b: bool,
    }

    fn points() -> (MyPointUnaligned, MyPointUnaligned) {
        (
            MyPointUnaligned {
                x: 3,
                y: 5,
                b: true,
            },
            MyPointUnaligned {
                x: 8,
                y: 19,
                b: true,
            },
        )
    }

    #[test]
    fn test_io_run() {
        utils::setup_logger();
        let program = Program::from(IO_ELF);
        let mut runtime = Runtime::new(program);
        let points = points();
        runtime.write_stdin(&points.0);
        runtime.write_stdin(&points.1);
        runtime.run();
        let added_point = runtime.read_stdout::<MyPointUnaligned>();
        assert_eq!(
            added_point,
            MyPointUnaligned {
                x: 11,
                y: 24,
                b: true
            }
        );
    }

    #[test]
    fn test_io_prove() {
        utils::setup_logger();
        let program = Program::from(IO_ELF);
        let mut runtime = Runtime::new(program);
        let points = points();
        runtime.write_stdin(&points.0);
        runtime.write_stdin(&points.1);
        runtime.run();
        let config = BabyBearBlake3::new();
        prove_core(config, &mut runtime);
    }
}
