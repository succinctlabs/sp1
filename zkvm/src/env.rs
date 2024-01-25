use crate::syscall::{sys_write, syscall_read};
use bincode;
use serde::de::{Deserialize, DeserializeOwned};
use serde::Serialize;

const FILE_DESCRIPTOR: u32 = 3;
pub struct MyReader {}

impl std::io::Read for MyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = buf.len();
        let mut aligned_len = len;
        if aligned_len % 4 != 0 {
            aligned_len += 4 - (aligned_len % 4);
        }
        let nwords = aligned_len / 4;
        let read_buf = vec![0u32; nwords];
        syscall_read(3, read_buf.as_ptr(), nwords);
        // TODO: copy the read_buf into buf, truncating if necessary.
        Ok(len)
    }
}

impl std::io::Write for MyReader {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let nbytes = buf.len();
        let write_buf = buf.as_ptr() as *const u8;
        sys_write(FILE_DESCRIPTOR, write_buf, nbytes);
        Ok(nbytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn read<T: DeserializeOwned>() -> T {
    let mut buf = [0u8; 32];
    let my_reader = MyReader {};
    let result = bincode::deserialize_from::<_, T>(my_reader);
    result.unwrap()
}

// pub fn read_slice(buf: &mut [u8]) {
//     let mut buf = [0u8; 32];
//     reader.read_exact(&mut buf)?;
//     Ok(buf.to_vec())
// }

pub fn write<T: Serialize>(value: &T) {
    let writer = MyReader {};
    bincode::serialize_into(writer, value).expect("Serialization failed");
}

// pub fn write_slice(buf: &[u8]) {
//     writer.write_all(&buf)?;
// }
