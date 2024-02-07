use bincode;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::Read;
use std::io::Write;

use crate::syscalls::syscall_read;
use crate::syscalls::syscall_write;

const FD_IO: u32 = 3;
const FD_HINT: u32 = 4;
pub struct SyscallReader {}

impl std::io::Read for SyscallReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = buf.len();
        unsafe {
            syscall_read(FD_IO, buf.as_mut_ptr(), len);
        }
        Ok(len)
    }
}

impl std::io::Write for SyscallReader {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let nbytes = buf.len();
        let write_buf = buf.as_ptr();
        unsafe {
            syscall_write(FD_IO, write_buf, nbytes);
        }
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
    bincode::serialize_into(writer, value).expect("serialization failed");
}

pub fn write_slice(buf: &[u8]) {
    let mut my_reader = SyscallReader {};
    my_reader.write_all(buf).unwrap();
}

pub struct HintWriter {}

impl std::io::Write for HintWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let nbytes = buf.len();
        let write_buf = buf.as_ptr();
        unsafe {
            syscall_write(FD_HINT, write_buf, nbytes);
        }
        Ok(nbytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn hint<T: Serialize>(value: &T) {
    let writer = HintWriter {};
    bincode::serialize_into(writer, value).expect("serialization failed");
}

pub fn hint_slice(buf: &[u8]) {
    let mut my_reader = HintWriter {};
    my_reader.write_all(buf).unwrap();
}
