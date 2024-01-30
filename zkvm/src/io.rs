use crate::syscall::{syscall_read, syscall_write};
use bincode;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::Read;
use std::io::Write;

const FILE_DESCRIPTOR: u32 = 3;
pub struct SyscallReader {}

impl std::io::Read for SyscallReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = buf.len();
        syscall_read(3, buf.as_mut_ptr(), len);
        Ok(len)
    }
}

impl std::io::Write for SyscallReader {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let nbytes = buf.len();
        let write_buf = buf.as_ptr();
        syscall_write(FILE_DESCRIPTOR, write_buf, nbytes);
        Ok(nbytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn read<T: DeserializeOwned>() -> T {
    let my_reader = SyscallReader {};
    let result = bincode::deserialize_from::<_, T>(my_reader);
    result.unwrap()
}

pub fn read_slice(buf: &mut [u8]) {
    let mut my_reader = SyscallReader {};
    my_reader.read_exact(buf).unwrap();
}

pub fn write<T: Serialize>(value: &T) {
    let writer = SyscallReader {};
    bincode::serialize_into(writer, value).expect("Serialization failed");
}

pub fn write_slice(buf: &[u8]) {
    let mut my_reader = SyscallReader {};
    my_reader.write_all(buf).unwrap();
}
