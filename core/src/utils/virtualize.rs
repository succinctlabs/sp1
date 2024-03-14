use std::{
    fs::File,
    io::{BufReader, BufWriter, Seek},
};

use serde::{de::DeserializeOwned, Serialize};

// A wrapper holding an object which can be virtualized when not needed and then materialized. This
// is useful when we want to store an object in a temporary file or remotely so we can preserve RAM.
pub trait Virtualize<T>: Default {
    /// Virtualize the object. This should only be called once.
    fn virtualize(&mut self, obj: T);

    /// Revirtualize the object. This can be used after the object has been virtualized and then
    /// materialized.
    fn revirtualize(&mut self, _obj: T) {}

    /// Materialize the object. This should only be called when the object is virtualized.
    fn materialize(&mut self) -> T;
}

pub struct InMemoryWrapper<T> {
    obj: Option<T>,
}

impl<T> Default for InMemoryWrapper<T> {
    fn default() -> Self {
        InMemoryWrapper { obj: None }
    }
}

impl<T> Virtualize<T> for InMemoryWrapper<T> {
    fn virtualize(&mut self, obj: T) {
        self.obj = Some(obj);
    }

    fn revirtualize(&mut self, obj: T) {
        // Because we took it out of the Option we have to put it back
        self.obj = Some(obj);
    }

    fn materialize(&mut self) -> T {
        self.obj.take().unwrap()
    }
}

impl<T> InMemoryWrapper<T> {
    pub fn new(obj: T) -> Self {
        InMemoryWrapper { obj: Some(obj) }
    }
}

pub struct TempFileWrapper<T> {
    file: Option<File>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Default for TempFileWrapper<T> {
    fn default() -> Self {
        let file = tempfile::tempfile().expect("failed to create temp file");
        TempFileWrapper {
            file: Some(file),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: DeserializeOwned + Serialize> Virtualize<T> for TempFileWrapper<T> {
    fn materialize(&mut self) -> T {
        let file = self.file.take().expect("file already taken");
        let mut reader = BufReader::new(file);
        reader
            .seek(std::io::SeekFrom::Start(0))
            .expect("failed to seek");
        bincode::deserialize_from(&mut reader).expect("failed to deserialize")
    }

    fn virtualize(&mut self, obj: T) {
        let mut writer = BufWriter::new(self.file.as_mut().unwrap());
        bincode::serialize_into(&mut writer, &obj).expect("failed to serialize");
    }
}

impl<T> TempFileWrapper<T> {
    pub fn new(file: File) -> Self {
        TempFileWrapper {
            file: Some(file),
            _phantom: std::marker::PhantomData,
        }
    }
}
