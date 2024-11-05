use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
pub enum RecursionProgramType {
    Core,
    Deferred,
    Compress,
    Shrink,
    Wrap,
}

/// A buffer of serializable/deserializable objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Buffer {
    pub data: Vec<u8>,
    #[serde(skip)]
    pub ptr: usize,
}

impl Buffer {
    pub const fn new() -> Self {
        Self { data: Vec::new(), ptr: 0 }
    }

    pub fn from(data: &[u8]) -> Self {
        Self { data: data.to_vec(), ptr: 0 }
    }

    /// Set the position ptr to the beginning of the buffer.
    pub fn head(&mut self) {
        self.ptr = 0;
    }

    /// Read the serializable object from the buffer.
    pub fn read<T: Serialize + DeserializeOwned>(&mut self) -> T {
        let result: T =
            bincode::deserialize(&self.data[self.ptr..]).expect("failed to deserialize");
        let nb_bytes = bincode::serialized_size(&result).expect("failed to get serialized size");
        self.ptr += nb_bytes as usize;
        result
    }

    pub fn read_slice(&mut self, slice: &mut [u8]) {
        slice.copy_from_slice(&self.data[self.ptr..self.ptr + slice.len()]);
        self.ptr += slice.len();
    }

    /// Write the serializable object from the buffer.
    pub fn write<T: Serialize>(&mut self, data: &T) {
        bincode::serialize_into(&mut self.data, data).expect("serialization failed");
    }

    /// Write the slice of bytes to the buffer.
    pub fn write_slice(&mut self, slice: &[u8]) {
        self.data.extend_from_slice(slice);
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestStruct {
        a: u32,
        b: String,
    }

    #[test]
    fn test_new() {
        let buffer = Buffer::new();
        assert!(buffer.data.is_empty());
        assert_eq!(buffer.ptr, 0);
    }

    #[test]
    fn test_from_slice() {
        let data: &[u8] = &[1, 2, 3, 4];
        let buffer = Buffer::from(data);
        assert_eq!(buffer.data, data);
        assert_eq!(buffer.ptr, 0);
    }

    #[test]
    fn test_head() {
        let data: &[u8] = &[1, 2, 3, 4];
        let mut buffer = Buffer::from(data);
        buffer.ptr = 2;
        buffer.head();
        assert_eq!(buffer.ptr, 0);
    }

    #[test]
    fn test_write_and_read() {
        let mut buffer = Buffer::new();
        let obj = TestStruct { a: 123, b: "test".to_string() };

        // Serialize `obj` using bincode for comparison
        let mut expected_data = Vec::new();
        bincode::serialize_into(&mut expected_data, &obj).expect("serialization failed");

        // Write `obj` to buffer and check if `buffer.data` matches `expected_data`
        buffer.write(&obj);
        assert_eq!(buffer.data, expected_data);
        assert_eq!(buffer.ptr, 0);

        let read_obj: TestStruct = buffer.read();
        assert_eq!(read_obj, obj);
        assert_eq!(buffer.ptr, buffer.data.len());
    }

    #[test]
    fn test_write_slice_and_read_slice() {
        let mut buffer = Buffer::new();
        let slice = [1, 2, 3, 4, 5];

        buffer.write_slice(&slice);
        assert_eq!(buffer.data, slice);

        let mut read_slice = [0; 5];
        buffer.head();
        buffer.read_slice(&mut read_slice);
        assert_eq!(read_slice, slice);
    }

    #[test]
    fn test_multiple_writes_and_reads() {
        let mut buffer = Buffer::new();
        let obj1 = TestStruct { a: 123, b: "first".to_string() };
        let obj2 = TestStruct { a: 456, b: "second".to_string() };

        buffer.write(&obj1);
        buffer.write(&obj2);

        buffer.head();
        let read_obj1: TestStruct = buffer.read();
        let read_obj2: TestStruct = buffer.read();

        assert_eq!(read_obj1, obj1);
        assert_eq!(read_obj2, obj2);
    }

    #[test]
    fn test_default() {
        let buffer: Buffer = Default::default();
        assert!(buffer.data.is_empty());
        assert_eq!(buffer.ptr, 0);
    }

    #[test]
    fn test_pointer_after_read() {
        let mut buffer = Buffer::new();
        let obj = TestStruct { a: 789, b: "pointer_test".to_string() };

        buffer.write(&obj);
        buffer.head();
        let start_ptr = buffer.ptr;

        let _read_obj: TestStruct = buffer.read();
        assert!(buffer.ptr > start_ptr, "Pointer should have advanced after read");
    }
}
