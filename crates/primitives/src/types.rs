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
        let mut tmp = Vec::new();
        bincode::serialize_into(&mut tmp, data).expect("serialization failed");
        self.data.extend(tmp);
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
