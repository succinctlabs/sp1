use super::Runtime;
use serde::de::DeserializeOwned;
use serde::Serialize;

impl std::io::Read for Runtime {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.get_output_slice(buf);
        Ok(buf.len())
    }
}

impl Runtime {
    pub fn add_input_slice(&mut self, input: &[u8]) {
        self.input_stream.extend(input);
    }

    pub fn add_input<T: Serialize>(&mut self, input: &T) {
        let mut buf = Vec::new();
        bincode::serialize_into(&mut buf, input).expect("Serialization failed");
        self.input_stream.extend(buf);
    }

    pub fn get_output_slice(&mut self, buf: &mut [u8]) {
        let len = buf.len();
        let start = self.output_stream_ptr;
        let end = start + len;
        assert!(end <= self.output_stream.len());
        buf.copy_from_slice(&self.output_stream[start..end]);
        self.output_stream_ptr = end;
    }

    pub fn get_output<T: DeserializeOwned>(&mut self) -> T {
        let result = bincode::deserialize_from::<_, T>(self);
        result.unwrap()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::runtime::program::Program;
    use crate::utils::prove_core;
    use log::debug;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct MyPoint {
        pub x: usize,
        pub y: usize,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct MyPointUnaligned {
        pub x: usize,
        pub y: usize,
        pub b: bool,
    }

    pub fn io_program() -> Program {
        Program::from_elf("../programs/io")
    }

    pub fn io_program_unaligned() -> Program {
        Program::from_elf("../programs/io_unaligned")
    }

    pub fn add_inputs(runtime: &mut Runtime) {
        let p1 = MyPoint { x: 3, y: 5 };
        let serialized = bincode::serialize(&p1).unwrap();
        runtime.add_input_slice(&serialized);
        let p2 = MyPoint { x: 8, y: 19 };
        runtime.add_input(&p2);
    }

    pub fn add_inputs_unaligned(runtime: &mut Runtime) {
        let p1 = MyPointUnaligned {
            x: 3,
            y: 5,
            b: false,
        };
        let serialized = bincode::serialize(&p1).unwrap();
        assert!(serialized.len() % 4 != 0);
        runtime.add_input_slice(&serialized);
        let p2 = MyPointUnaligned {
            x: 8,
            y: 19,
            b: true,
        };
        runtime.add_input(&p2);
    }

    #[test]
    fn test_io_run() {
        if env_logger::try_init().is_err() {
            debug!("Logger already initialized")
        }
        let program = io_program();
        let mut runtime = Runtime::new(program);
        add_inputs(&mut runtime);
        runtime.run();
        let added_point: MyPoint = runtime.get_output();
        assert_eq!(added_point, MyPoint { x: 11, y: 24 });
    }

    #[test]
    fn test_io_prove() {
        let program = io_program();
        let mut runtime = Runtime::new(program);
        add_inputs(&mut runtime);
        runtime.run();
        prove_core(&mut runtime);
    }

    #[test]
    fn test_io_unaligned_run() {
        if env_logger::try_init().is_err() {
            debug!("Logger already initialized")
        }
        let program = io_program_unaligned();
        let mut runtime = Runtime::new(program);
        add_inputs_unaligned(&mut runtime);
        runtime.run();
        let added_point: MyPointUnaligned = runtime.get_output();
        assert_eq!(
            added_point,
            MyPointUnaligned {
                x: 11,
                y: 24,
                b: false
            }
        );
    }

    #[test]
    fn test_io_unaligned_prove() {
        let program = io_program_unaligned();
        let mut runtime = Runtime::new(program);
        add_inputs_unaligned(&mut runtime);
        runtime.run();
        prove_core(&mut runtime);
    }
}
