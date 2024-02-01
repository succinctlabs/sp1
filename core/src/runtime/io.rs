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
    use crate::utils::tests::IO_ELF;
    use crate::utils::{prove_core, setup_logger};
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
        Program::from(IO_ELF)
    }

    pub fn add_inputs(runtime: &mut Runtime) {
        let p1 = MyPoint { x: 3, y: 5 };
        let serialized = bincode::serialize(&p1).unwrap();
        runtime.add_input_slice(&serialized);
        let p2 = MyPoint { x: 8, y: 19 };
        runtime.add_input(&p2);
    }

    #[test]
    fn test_io_run() {
        setup_logger();
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
}
