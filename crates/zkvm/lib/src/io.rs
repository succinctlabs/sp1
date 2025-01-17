#![allow(unused_unsafe)]
use crate::{read_vec_raw, syscall_write, ReadVecResult};
use serde::{de::DeserializeOwned, Serialize};
use std::io::{Result, Write};

pub use sp1_primitives::consts::fd::*;

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

/// Read a buffer from the input stream. The buffer is read into uninitialized memory.
///
/// When the `bump` feature is enabled, the buffer is read into a new buffer allocated by the
/// program.
///
/// When the `embedded` feature is enabled, the buffer is read into the reserved input region.
///
/// When there is no allocator selected, the program will fail to compile.
///
/// ### Examples
/// ```ignore
/// let data: Vec<u8> = sp1_zkvm::io::read_vec();
/// ```
#[track_caller]
pub fn read_vec() -> Vec<u8> {
    let ReadVecResult { ptr, len, capacity } = unsafe { read_vec_raw() };

    if ptr.is_null() {
        panic!(
            "Tried to read from the input stream, but it was empty @ {} \n
            Was the correct data written into SP1Stdin?",
            std::panic::Location::caller()
        )
    }

    unsafe { Vec::from_raw_parts(ptr, len, capacity) }
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
#[track_caller]
pub fn read<T: DeserializeOwned>() -> T {
    let ReadVecResult { ptr, len, capacity } = unsafe { read_vec_raw() };

    if ptr.is_null() {
        panic!(
            "Tried to read from the input stream, but it was empty @ {} \n
            Was the correct data written into SP1Stdin?",
            std::panic::Location::caller()
        )
    }

    // 1. `ptr` was allocated using alloc
    // 2. Assume that the allocator in the VM doesn't deallocate in the input space.
    // 3. Size and length are correct from above. Length is <= capacity.
    let vec = unsafe { Vec::from_raw_parts(ptr, len, capacity) };

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
