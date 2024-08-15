#![allow(unused_unsafe)]
use crate::{syscall_hint_len, syscall_hint_read, syscall_write};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    alloc::Layout,
    io::{Result, Write},
};

/// The file descriptor for public values.
pub const FD_PUBLIC_VALUES: u32 = 3;

/// The file descriptor for hints.
pub const FD_HINT: u32 = 4;

/// The file descriptor for the `ecreover` hook.
pub const FD_ECRECOVER_HOOK: u32 = 5;

/// A writer that writes to a file descriptor inside the zkVM.
struct SyscallWriter {
    fd: u32,
}

impl Write for SyscallWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let nbytes = buf.len();
        let write_buf = buf.as_ptr();
        unsafe {
            syscall_write(self.fd, write_buf, nbytes);
        }
        Ok(nbytes)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Read a buffer from the input stream.
///
/// ### Examples
/// ```ignore
/// let data: Vec<u8> = sp1_zkvm::io::read_vec();
/// ```
pub fn read_vec() -> Vec<u8> {
    // Round up to the nearest multiple of 4 so that the memory allocated is in whole words
    let len = unsafe { syscall_hint_len() };
    let capacity = (len + 3) / 4 * 4;

    // Allocate a buffer of the required length that is 4 byte aligned
    let layout = Layout::from_size_align(capacity, 4).expect("vec is too large");
    let ptr = unsafe { std::alloc::alloc(layout) };

    // SAFETY:
    // 1. `ptr` was allocated using alloc
    // 2. We assuume that the VM global allocator doesn't dealloc
    // 3/6. Size is correct from above
    // 4/5. Length is 0
    // 7. Layout::from_size_align already checks this
    let mut vec = unsafe { Vec::from_raw_parts(ptr, 0, capacity) };

    // Read the vec into uninitialized memory. The syscall assumes the memory is uninitialized,
    // which should be true because the allocator does not dealloc, so a new alloc should be fresh.
    unsafe {
        syscall_hint_read(ptr, len);
        vec.set_len(len);
    }
    vec
}

/// Read a deserializable object from the input stream.
///
/// ### Examples
/// ```ignore
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct MyStruct {
///     a: u32,
///     b: u32,
/// }
///
/// let data: MyStruct = sp1_zkvm::io::read();
/// ```
pub fn read<T: DeserializeOwned>() -> T {
    let vec = read_vec();
    bincode::deserialize(&vec).expect("deserialization failed")
}

/// Commit a serializable object to the public values stream.
///
/// ### Examples
/// ```ignore
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct MyStruct {
///     a: u32,
///     b: u32,
/// }
///
/// let data = MyStruct {
///     a: 1,
///     b: 2,
/// };
/// sp1_zkvm::io::commit(&data);
/// ```
pub fn commit<T: Serialize>(value: &T) {
    let writer = SyscallWriter { fd: FD_PUBLIC_VALUES };
    bincode::serialize_into(writer, value).expect("serialization failed");
}

/// Commit bytes to the public values stream.
///
/// ### Examples
/// ```ignore
/// let data = vec![1, 2, 3, 4];
/// sp1_zkvm::io::commit_slice(&data);
/// ```
pub fn commit_slice(buf: &[u8]) {
    let mut my_writer = SyscallWriter { fd: FD_PUBLIC_VALUES };
    my_writer.write_all(buf).unwrap();
}

/// Hint a serializable object to the hint stream.
///
/// ### Examples
/// ```ignore
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct MyStruct {
///     a: u32,
///     b: u32,
/// }
///
/// let data = MyStruct {
///     a: 1,
///     b: 2,
/// };
/// sp1_zkvm::io::hint(&data);
/// ```
pub fn hint<T: Serialize>(value: &T) {
    let writer = SyscallWriter { fd: FD_HINT };
    bincode::serialize_into(writer, value).expect("serialization failed");
}

/// Hint bytes to the hint stream.
///
/// ### Examples
/// ```ignore
/// let data = vec![1, 2, 3, 4];
/// sp1_zkvm::io::hint_slice(&data);
/// ```
pub fn hint_slice(buf: &[u8]) {
    let mut my_reader = SyscallWriter { fd: FD_HINT };
    my_reader.write_all(buf).unwrap();
}

/// Write the data `buf` to the file descriptor `fd`.
///
/// ### Examples
/// ```ignore
/// let data = vec![1, 2, 3, 4];
/// sp1_zkvm::io::write(3, &data);
/// ```
pub fn write(fd: u32, buf: &[u8]) {
    SyscallWriter { fd }.write_all(buf).unwrap();
}
