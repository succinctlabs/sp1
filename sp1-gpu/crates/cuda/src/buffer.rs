use std::mem::MaybeUninit;

use slop_alloc::{mem::CopyError, Buffer, HasBackend};

use crate::{DeviceCopy, TaskScope};

pub struct DeviceBuffer<T> {
    buf: Buffer<T, TaskScope>,
}

impl<T: DeviceCopy> HasBackend for DeviceBuffer<T> {
    type Backend = TaskScope;
    fn backend(&self) -> &TaskScope {
        self.buf.backend()
    }
}

impl<T: DeviceCopy> DeviceBuffer<T> {
    /// Create a new device buffer with the given capacity in the specified scope.
    pub fn with_capacity_in(capacity: usize, scope: TaskScope) -> Self {
        Self { buf: Buffer::with_capacity_in(capacity, scope) }
    }

    /// Creates a DeviceBuffer from an existing Buffer on the device.
    pub fn from_raw(buf: Buffer<T, TaskScope>) -> Self {
        Self { buf }
    }

    /// Returns a raw pointer to the device buffer's data.
    pub fn as_ptr(&self) -> *const T {
        self.buf.as_ptr()
    }

    /// Returns a mutable raw pointer to the device buffer's data.
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.buf.as_mut_ptr()
    }

    /// Copy the contents of this buffer to the host slice `dst`.
    ///
    /// # Safety
    ///
    /// The memory being copied to might be pinned, so the copy will not block. Therefore, the
    /// caller must ensure that the source buffer lives long enough for the copy to complete.
    pub unsafe fn copy_to_host_slice(&self, dst: &mut [MaybeUninit<T>]) -> Result<(), CopyError> {
        self.buf.copy_into_host(dst)
    }

    /// Extend the device buffer by copying data from the host slice `src`.
    ///
    /// # Safety
    /// See [Buffer::extend_from_host_slice]
    pub unsafe fn extend_from_host_slice(&mut self, src: &[T]) -> Result<(), CopyError> {
        self.buf.extend_from_host_slice(src)
    }

    pub fn to_host(&self) -> Result<Vec<T>, CopyError> {
        let len = self.buf.len();
        let mut host_vec = Vec::with_capacity(len);
        // Safety: The memory being allocated is not pinned, so the copy will block until completed.
        // After copying, we set the length since the copy has initialized the memory.
        unsafe {
            self.copy_to_host_slice(host_vec.spare_capacity_mut())?;
            host_vec.set_len(len);
        }
        Ok(host_vec)
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Forcibly set the length of the buffer.
    ///
    /// # Safety
    ///  See [Buffer::set_len]
    pub unsafe fn set_len(&mut self, len: usize) {
        self.buf.set_len(len);
    }

    #[allow(clippy::ptr_arg)]
    pub fn extend_from_vec(&mut self, host_data: &Vec<T>) -> Result<(), CopyError> {
        // Safety: The memory being copied from is not pinned, so the copy will block until completed.
        unsafe { self.extend_from_host_slice(host_data) }
    }

    pub fn extend(&mut self, host_data: &Buffer<T>) -> Result<(), CopyError> {
        // Safety: The memory being copied from is not pinned, so the copy will block until completed.
        unsafe { self.extend_from_host_slice(host_data) }
    }

    /// Creates a DeviceBuffer by copying data from a host Buffer.
    pub fn from_host(host_buf: &Buffer<T>, scope: &TaskScope) -> Result<Self, CopyError> {
        let mut device_buf = Self::with_capacity_in(host_buf.len(), scope.clone());
        device_buf.extend(host_buf)?;
        Ok(device_buf)
    }

    /// Creates a DeviceBuffer by copying data from a host slice.
    pub fn from_host_slice(host_slice: &[T], scope: &TaskScope) -> Result<Self, CopyError> {
        let mut device_buf = Self::with_capacity_in(host_slice.len(), scope.clone());
        // Safety: The memory being copied from is not pinned, so the copy will block until completed.
        unsafe { device_buf.extend_from_host_slice(host_slice)? };
        Ok(device_buf)
    }

    pub fn into_inner(self) -> Buffer<T, TaskScope> {
        self.buf
    }

    /// # Safety
    /// See [Buffer::assume_init]
    pub unsafe fn assume_init(&mut self) {
        self.buf.assume_init();
    }
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};
    use sp1_primitives::SP1Field;

    use super::*;

    #[test]
    fn test_copy_buffer_into_backend() {
        let mut rng = thread_rng();
        let buffer: Vec<SP1Field> = (0..10000).map(|_| rng.gen::<SP1Field>()).collect();

        let buffer_back = crate::run_sync_in_place(|t| {
            let mut device_buffer = DeviceBuffer::with_capacity_in(buffer.len(), t);
            device_buffer.extend_from_vec(&buffer).unwrap();
            device_buffer.to_host().unwrap()
        })
        .unwrap();

        assert_eq!(buffer_back, buffer);
    }
}
