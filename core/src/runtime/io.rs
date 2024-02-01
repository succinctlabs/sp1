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
        self.input_stream.extend(buf);
    }

    pub fn write_stdin_slice(&mut self, input: &[u8]) {
        self.input_stream.extend(input);
    }

    pub fn read_stdout<T: DeserializeOwned>(&mut self) -> T {
        let result = bincode::deserialize_from::<_, T>(self);
        result.unwrap()
    }

    pub fn read_stdout_slice(&mut self, buf: &mut [u8]) {
        let len = buf.len();
        let start = self.output_stream_ptr;
        let end = start + len;
        assert!(end <= self.output_stream.len());
        buf.copy_from_slice(&self.output_stream[start..end]);
        self.output_stream_ptr = end;
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::runtime::Program;
    use crate::utils::tests::IO_ELF;
    use crate::utils::{self, prove_core};
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
        prove_core(&mut runtime);
    }
}
