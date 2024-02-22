#![allow(unused_unsafe)]
use crate::syscall_magic_read;
use crate::{syscall_read, syscall_write};
use bincode;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::Read;
use std::io::Write;

const FD_IO: u32 = 3;
const FD_HINT: u32 = 4;
pub struct SyscallReader {
    fd: u32,
}

impl std::io::Read for SyscallReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = buf.len();
        unsafe {
            syscall_read(self.fd, buf.as_mut_ptr(), len);
        }
        Ok(len)
    }
}
pub struct SyscallWriter {
    fd: u32,
}

impl std::io::Write for SyscallWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let nbytes = buf.len();
        let write_buf = buf.as_ptr();
        unsafe {
            syscall_write(self.fd, write_buf, nbytes);
        }
        Ok(nbytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn read<T: DeserializeOwned>() -> T {
    let my_reader = SyscallReader { fd: FD_IO };
    let result = bincode::deserialize_from::<_, T>(my_reader);
    result.unwrap()
}

pub fn read_slice(buf: &mut [u8]) {
    let mut my_reader = SyscallReader { fd: FD_IO };
    my_reader.read_exact(buf).unwrap();
}

pub fn write<T: Serialize>(value: &T) {
    let writer = SyscallWriter { fd: FD_IO };
    bincode::serialize_into(writer, value).expect("serialization failed");
}

pub fn write_slice(buf: &[u8]) {
    let mut my_reader = SyscallWriter { fd: FD_IO };
    my_reader.write_all(buf).unwrap();
}

pub fn hint<T: Serialize>(value: &T) {
    let writer = SyscallWriter { fd: FD_HINT };
    bincode::serialize_into(writer, value).expect("serialization failed");
}

pub fn hint_slice(buf: &[u8]) {
    let mut my_reader = SyscallWriter { fd: FD_HINT };
    my_reader.write_all(buf).unwrap();
}

pub fn read_magic<T: Copy>() -> &'static T {
    unsafe {
        let result = syscall_magic_read();
        // std::slice::from_raw_parts(result.ptr, result.len / std::mem::size_of::<T>()).as_ptr()
        // assert_eq!(result.len, std::mem::size_of::<T>());
        // return casted pointer
        // result.ptr as &'static T
        // let static_ref: &'static T = unsafe { std::mem::transmute(result.ptr) };
        // static_ref
        &*(result.ptr as *const T)

        // &std::mem::transmute::<&[u8], T>(std::slice::from_raw_parts(
        //     result.ptr,
        //     result.len / std::mem::size_of::<T>(),
        // ))
    }
    // todo!()
}
