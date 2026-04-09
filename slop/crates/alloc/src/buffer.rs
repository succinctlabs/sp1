//! Fixed-capacity buffer with customizable memory backends.
//!
//! This module provides a `Buffer<T, A>` type, which is a contiguous array type
//! with heap-allocated contents. Unlike `Vec<T>`, buffers have a fixed capacity
//! determined at creation time and cannot grow beyond this capacity.
//!
//! # Key Differences from `Vec<T>`
//!
//! - **Fixed Capacity**: Buffers cannot reallocate to grow beyond their initial capacity
//! - **Backend Support**: Works with different memory allocators (CPU, GPU, etc.)
//! - **CPU Backend Exception**: Only `Buffer<T, CpuBackend>` supports capacity growth through
//!   conversion to/from `Vec<T>`
//!
//! # Examples
//!
//! ```rust,ignore
//! let mut buffer: Buffer<i32> = Buffer::with_capacity(10);
//! // The buffer can hold up to 10 elements
//! assert_eq!(buffer.len(), 0);
//! assert_eq!(buffer.capacity(), 10);
//!
//! // For non-CPU backends, this is the maximum capacity
//! // Attempting to exceed it will panic
//! ```

use serde::{Deserialize, Serialize, Serializer};
use slop_algebra::{ExtensionField, Field};

use crate::{
    backend::{Backend, CpuBackend, GLOBAL_CPU_BACKEND},
    mem::{CopyDirection, CopyError},
    slice::Slice,
    HasBackend, Init, RawBuffer, TryReserveError,
};
use std::{
    alloc::Layout,
    mem::{ManuallyDrop, MaybeUninit},
    ops::{
        Deref, DerefMut, Index, IndexMut, Range, RangeFrom, RangeFull, RangeInclusive, RangeTo,
        RangeToInclusive,
    },
};

/// A fixed-capacity buffer with heap-allocated contents.
///
/// This type provides a contiguous array with a fixed maximum capacity. For most backends,
/// the capacity is immutable after creation. Only `Buffer<T, CpuBackend>` can grow by
/// converting to/from `Vec<T>` internally.
///
/// # Type Parameters
///
/// - `T`: The type of elements stored in the buffer
/// - `A`: The backend allocator type (defaults to `CpuBackend`)
///
/// # Guarantees
///
/// - The memory it points to is allocated by the backend allocator `A`
/// - `length` <= `capacity`
/// - The first `length` values are properly initialized
/// - The capacity remains fixed for the lifetime of the buffer (except for `CpuBackend`)
#[derive(Debug)]
#[repr(C)]
pub struct Buffer<T, A: Backend = CpuBackend> {
    buf: RawBuffer<T, A>,
    len: usize,
}

unsafe impl<T, A: Backend> Send for Buffer<T, A> {}
unsafe impl<T, A: Backend> Sync for Buffer<T, A> {}

impl<T, A> Buffer<T, A>
where
    A: Backend,
{
    /// Constructs a new, empty `Buffer<T, A>` with the specified capacity
    /// using the provided allocator.
    ///
    /// The buffer will be able to hold exactly `capacity` elements. For non-CPU
    /// backends, this capacity is fixed and cannot be exceeded. Attempting to
    /// add more elements than the capacity will result in a panic.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity exceeds `isize::MAX` bytes.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::{Buffer, CpuBackend, GLOBAL_CPU_BACKEND};
    ///
    /// let mut buffer = Buffer::with_capacity_in(10, GLOBAL_CPU_BACKEND);
    ///
    /// // The buffer contains no items, even though it has capacity for more
    /// assert_eq!(buffer.len(), 0);
    /// assert_eq!(buffer.capacity(), 10);
    /// ```
    #[inline]
    #[must_use]
    pub fn with_capacity_in(capacity: usize, allocator: A) -> Self {
        let buf = RawBuffer::with_capacity_in(capacity, allocator);
        Self { buf, len: 0 }
    }

    /// Tries to construct a new, empty `Buffer<T, A>` with the specified
    /// capacity using the provided allocator.
    ///
    /// This is the fallible version of [`with_capacity_in`]. It returns an error
    /// if the allocation fails instead of panicking.
    ///
    /// # Errors
    ///
    /// Returns `Err(TryReserveError)` if the allocator fails to allocate memory.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::{Buffer, CpuBackend, GLOBAL_CPU_BACKEND};
    ///
    /// match Buffer::<i32, CpuBackend>::try_with_capacity_in(10, GLOBAL_CPU_BACKEND) {
    ///     Ok(buffer) => {
    ///         assert_eq!(buffer.len(), 0);
    ///         assert_eq!(buffer.capacity(), 10);
    ///     }
    ///     Err(e) => println!("Failed to allocate: {:?}", e),
    /// }
    /// ```
    ///
    /// [`with_capacity_in`]: Buffer::with_capacity_in
    #[inline]
    pub fn try_with_capacity_in(capacity: usize, allocator: A) -> Result<Self, TryReserveError> {
        let buf = RawBuffer::try_with_capacity_in(capacity, allocator)?;
        Ok(Self { buf, len: 0 })
    }

    /// Returns a new buffer from a pointer, length, and capacity.
    ///
    /// # Safety
    ///
    /// The pointer must be valid, it must have allocated memory in the size of
    /// capacity * size_of<T>, and the first `len` elements of the buffer must be initialized or
    /// about to be initialized in a foreign call.
    pub unsafe fn from_raw_parts(ptr: *mut T, length: usize, capacity: usize, alloc: A) -> Self {
        Self { buf: RawBuffer::from_raw_parts_in(ptr, capacity, alloc), len: length }
    }

    /// Returns the number of elements in the buffer, also referred to as its 'length'.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let buffer = buffer![1, 2, 3];
    /// assert_eq!(buffer.len(), 3);
    /// ```
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns the total number of elements the buffer can hold.
    ///
    /// For non-CPU backends, this is a fixed value that cannot change.
    /// For CPU backends, this may increase if operations like `push` or
    /// `extend` trigger internal reallocation through `Vec` conversion.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let buffer: Buffer<i32> = Buffer::with_capacity(10);
    /// assert_eq!(buffer.capacity(), 10);
    /// ```
    #[inline]
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// # Safety
    ///
    /// This function is unsafe because it enables bypassing the lifetime of the buffer.
    #[inline]
    pub unsafe fn owned_unchecked(&self) -> ManuallyDrop<Self> {
        self.owned_unchecked_in(self.allocator().clone())
    }

    /// # Safety
    ///
    /// This function is unsafe because it enables bypassing the lifetime of the buffer.
    #[inline]
    pub unsafe fn owned_unchecked_in(&self, allocator: A) -> ManuallyDrop<Self> {
        let ptr = self.as_ptr() as *mut T;
        let len = self.len();
        let cap = self.capacity();
        ManuallyDrop::new(Self::from_raw_parts(ptr, len, cap, allocator))
    }

    /// Returns `true` if the buffer contains no elements.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut buffer = Buffer::with_capacity(10);
    /// assert!(buffer.is_empty());
    ///
    /// buffer.push(1);
    /// assert!(!buffer.is_empty());
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns a raw pointer to the buffer's elements.
    ///
    /// The caller must ensure that the buffer outlives the pointer this function
    /// returns, or else it will end up pointing to garbage. For CPU backends,
    /// modifying the buffer may cause its buffer to be reallocated, which would
    /// also make any pointers to it invalid.
    ///
    /// The pointer is valid for reads of up to `len() * size_of::<T>()` bytes.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let buffer = buffer![1, 2, 4];
    /// let buffer_ptr = buffer.as_ptr();
    ///
    /// unsafe {
    ///     for i in 0..buffer.len() {
    ///         assert_eq!(*buffer_ptr.add(i), [1, 2, 4][i]);
    ///     }
    /// }
    /// ```
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.buf.ptr()
    }

    /// Returns an unsafe mutable pointer to the buffer's elements.
    ///
    /// The caller must ensure that the buffer outlives the pointer this function
    /// returns, or else it will end up pointing to garbage. For CPU backends,
    /// modifying the buffer may cause its buffer to be reallocated, which would
    /// also make any pointers to it invalid.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut buffer = buffer![1, 2, 4];
    /// let buffer_ptr = buffer.as_mut_ptr();
    ///
    /// unsafe {
    ///     for i in 0..buffer.len() {
    ///         *buffer_ptr.add(i) = i as i32;
    ///     }
    /// }
    ///
    /// assert_eq!(&*buffer, &[0, 1, 2]);
    /// ```
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.buf.ptr()
    }

    /// Forces the length of the buffer to `new_len`.
    ///
    /// This is a low-level operation that maintains none of the normal invariants
    /// of the type. Normally changing the length of a buffer is done using one of
    /// the safe operations instead, such as [`push`], [`pop`], [`extend_from_slice`],
    /// or [`clear`].
    ///
    /// # Safety
    ///
    /// - `new_len` must be less than or equal to [`capacity()`].
    /// - The elements at `old_len..new_len` must be initialized.
    ///
    /// # Examples
    ///
    /// This method can be useful for situations in which the buffer is serving as a
    /// buffer for other code, particularly over FFI. As an example, if FFI code writes
    /// values into the buffer, then this can be used to change the length of the buffer
    /// to match the number of elements written.
    ///
    /// ```rust,ignore
    /// let mut buffer = Buffer::with_capacity(3);
    /// unsafe {
    ///     let ptr = buffer.as_mut_ptr();
    ///     // Overwrite memory with 3, 2, 1
    ///     ptr.write(3);
    ///     ptr.add(1).write(2);
    ///     ptr.add(2).write(1);
    ///
    ///     // Set the length to 3 after writing
    ///     buffer.set_len(3);
    /// }
    /// assert_eq!(&*buffer, &[3, 2, 1]);
    /// ```
    ///
    /// [`capacity()`]: Buffer::capacity
    /// [`push`]: Buffer::push
    /// [`pop`]: Buffer::pop
    /// [`extend_from_slice`]: Buffer::extend_from_slice
    /// [`clear`]: Buffer::clear
    #[inline]
    pub unsafe fn set_len(&mut self, new_len: usize) {
        self.len = new_len;
    }

    /// Assumes that the entire capacity of the buffer is initialized.
    ///
    /// This sets the buffer's length to its capacity, effectively marking all
    /// allocated memory as containing valid values of type `T`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that all elements up to the buffer's capacity are
    /// properly initialized before calling this method. Calling this on a buffer
    /// with uninitialized memory will lead to undefined behavior when those
    /// elements are accessed.
    ///
    /// This is particularly dangerous for types with drop implementations, as
    /// dropping uninitialized memory can cause crashes or worse.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut buffer: Buffer<u8> = Buffer::with_capacity(4);
    ///
    /// unsafe {
    ///     // Initialize all 4 bytes
    ///     buffer.as_mut_ptr().write_bytes(0, 4);
    ///
    ///     // Now we can safely assume all memory is initialized
    ///     buffer.assume_init();
    /// }
    ///
    /// assert_eq!(buffer.len(), 4);
    /// assert_eq!(&*buffer, &[0, 0, 0, 0]);
    /// ```
    #[inline]
    pub unsafe fn assume_init(&mut self) {
        let cap = self.capacity();
        self.set_len(cap);
    }

    /// Copies all elements from `src` into `self`, using `copy_nonoverlapping`.
    ///
    /// The length of `src` must be the same as `self`. This method overwrites the
    /// entire contents of the buffer.
    ///
    /// # Panics
    ///
    /// This function will panic if the two slices have different lengths.
    ///
    /// # Errors
    ///
    /// Returns `Err(CopyError)` if the allocator fails to perform the copy operation.
    ///
    /// # Safety
    ///
    /// This operation is potentially asynchronous. The caller must ensure the memory
    /// of the source slice remains valid for the duration of the operation. For backends
    /// that perform asynchronous operations (like GPU backends), the source memory must
    /// not be freed or modified until the operation completes.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut buffer = Buffer::with_capacity(3);
    /// unsafe {
    ///     buffer.set_len(3); // Must set length first
    ///     buffer.copy_from_host_slice(&[1, 2, 3]).unwrap();
    /// }
    /// assert_eq!(&*buffer, &[1, 2, 3]);
    /// ```
    #[track_caller]
    pub unsafe fn copy_from_host_slice(&mut self, src: &[T]) -> Result<(), CopyError> {
        // The panic code path was put into a cold function to not bloat the
        // call site.
        #[inline(never)]
        #[cold]
        #[track_caller]
        fn len_mismatch_fail(dst_len: usize, src_len: usize) -> ! {
            panic!(
                "source slice length ({src_len}) does not match destination slice length ({dst_len})",
            );
        }

        if self.len() != src.len() {
            len_mismatch_fail(self.len(), src.len());
        }

        let layout = Layout::array::<T>(src.len()).unwrap();

        unsafe {
            self.buf.allocator().copy_nonoverlapping(
                src.as_ptr() as *const u8,
                self.buf.ptr() as *mut u8,
                layout.size(),
                CopyDirection::HostToDevice,
            )
        }
    }

    /// Returns a reference to the underlying allocator.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::{Buffer, CpuBackend, GLOBAL_CPU_BACKEND};
    ///
    /// let buffer: Buffer<i32, CpuBackend> = Buffer::with_capacity(10);
    /// let allocator = buffer.allocator();
    /// // Can use the allocator reference for other operations
    /// ```
    #[inline]
    pub fn allocator(&self) -> &A {
        self.buf.allocator()
    }

    /// Returns a mutable reference to the underlying allocator.
    ///
    /// # Safety
    ///
    /// This method is unsafe because modifying the allocator while the buffer
    /// is in use could lead to undefined behavior. The caller must ensure that
    /// any modifications to the allocator do not invalidate the buffer's
    /// existing allocations or violate any invariants.
    #[inline]
    pub unsafe fn allocator_mut(&mut self) -> &mut A {
        self.buf.allocator_mut()
    }

    /// Appends all elements from a device slice into `self`.
    ///
    /// This extends the buffer by copying elements from another slice on the same device.
    /// The operation uses `copy_nonoverlapping` and is typically more efficient than
    /// host-to-device copies.
    ///
    /// # Panics
    ///
    /// This function will panic if the resulting length exceeds the buffer's capacity.
    ///
    /// # Errors
    ///
    /// Returns `Err(CopyError)` if the allocator fails to perform the copy operation.
    ///
    /// # Safety
    ///
    /// While this method is safe to call, the operation may be asynchronous depending
    /// on the backend. The implementation ensures proper memory handling.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut buffer1 = buffer![1, 2, 3];
    /// let mut buffer2 = Buffer::with_capacity(6);
    ///
    /// // Copy elements from buffer1 to buffer2
    /// buffer2.extend_from_device_slice(&buffer1[..]).unwrap();
    /// assert_eq!(buffer2.len(), 3);
    /// ```
    #[track_caller]
    pub fn extend_from_device_slice(&mut self, src: &Slice<T, A>) -> Result<(), CopyError> {
        // The panic code path was put into a cold function to not bloat the
        // call site.
        #[inline(never)]
        #[cold]
        #[track_caller]
        fn capacity_fail(dst_len: usize, src_len: usize, cap: usize) -> ! {
            panic!(
                "source slice length ({src_len}) too long for buffer of length ({dst_len}) and capacity ({cap})"
            );
        }

        if self.len() + src.len() > self.capacity() {
            capacity_fail(self.len(), src.len(), self.capacity());
        }

        let layout = Layout::array::<T>(src.len()).unwrap();

        unsafe {
            self.buf.allocator().copy_nonoverlapping(
                src.as_ptr() as *const u8,
                self.buf.ptr().add(self.len()) as *mut u8,
                layout.size(),
                CopyDirection::DeviceToDevice,
            )?;
        }

        // Extend the length of the buffer to include the new elements.
        self.len += src.len();

        Ok(())
    }

    /// Appends all elements from a host slice into `self`.
    ///
    /// This extends the buffer by copying elements from CPU memory. For non-CPU backends,
    /// this involves a host-to-device transfer.
    ///
    /// # Panics
    ///
    /// This function will panic if the resulting length exceeds the buffer's capacity.
    ///
    /// # Errors
    ///
    /// Returns `Err(CopyError)` if the allocator fails to perform the copy operation.
    ///
    /// # Safety
    ///
    /// While this method is safe to call, the operation may be asynchronous depending
    /// on the backend. The implementation ensures the source memory remains valid
    /// during the operation.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut buffer = Buffer::with_capacity(5);
    /// buffer.extend_from_host_slice(&[1, 2, 3]).unwrap();
    /// assert_eq!(buffer.len(), 3);
    ///
    /// buffer.extend_from_host_slice(&[4, 5]).unwrap();
    /// assert_eq!(buffer.len(), 5);
    /// ```
    #[track_caller]
    pub fn extend_from_host_slice(&mut self, src: &[T]) -> Result<(), CopyError> {
        // The panic code path was put into a cold function to not bloat the
        // call site.
        #[inline(never)]
        #[cold]
        #[track_caller]
        fn capacity_fail(dst_len: usize, src_len: usize, cap: usize) -> ! {
            panic!(
                "source slice length ({src_len}) too long for buffer of length ({dst_len}) and capacity ({cap})"
            );
        }

        if self.len() + src.len() > self.capacity() {
            capacity_fail(self.len(), src.len(), self.capacity());
        }

        let layout = Layout::array::<T>(src.len()).unwrap();

        unsafe {
            self.buf.allocator().copy_nonoverlapping(
                src.as_ptr() as *const u8,
                self.buf.ptr().add(self.len()) as *mut u8,
                layout.size(),
                CopyDirection::HostToDevice,
            )?;
        }

        // Extend the length of the buffer to include the new elements.
        self.len += src.len();

        Ok(())
    }

    /// Copies all elements from `self` into `dst`, using `copy_nonoverlapping`.
    ///
    /// The length of `dst` must be the same as `self`.
    ///
    /// **Note**: This function might be blocking.
    ///
    /// # Safety
    ///
    /// This operation is potentially asynchronous. The caller must insure the memory of the
    /// destination is valid for the duration of the operation.
    #[track_caller]
    pub unsafe fn copy_into_host(&self, dst: &mut [MaybeUninit<T>]) -> Result<(), CopyError> {
        // The panic code path was put into a cold function to not bloat the
        // call site.
        #[inline(never)]
        #[cold]
        #[track_caller]
        fn len_mismatch_fail(dst_len: usize, src_len: usize) -> ! {
            panic!(
                "source slice length ({src_len}) does not match destination slice length ({dst_len})",
            );
        }

        if self.len() != dst.len() {
            len_mismatch_fail(dst.len(), self.len());
        }

        let layout = Layout::array::<T>(dst.len()).unwrap();

        unsafe {
            self.buf.allocator().copy_nonoverlapping(
                self.buf.ptr() as *const u8,
                dst.as_mut_ptr() as *mut u8,
                layout.size(),
                CopyDirection::DeviceToHost,
            )
        }
    }

    /// Copies all elements from `self` into a newely allocated [Vec<T>] and returns it.
    ///
    /// # Safety
    ///  See [Buffer::copy_into_host]
    pub unsafe fn copy_into_host_vec(&self) -> Vec<T> {
        let mut vec = Vec::with_capacity(self.len());
        self.copy_into_host(vec.spare_capacity_mut()).unwrap();
        unsafe {
            vec.set_len(self.len());
        }
        vec
    }

    /// Copies all elements from `self` into a newely allocated [Vec<T>] and returns it.
    ///
    /// # Safety
    ///  See [Buffer::copy_into_host]
    pub unsafe fn copy_into_host_buffer(&self) -> Buffer<T, CpuBackend> {
        let vec = self.copy_into_host_vec();
        Buffer::from(vec)
    }

    /// Sets `len` bytes of memory starting at the current length to `value`.
    ///
    /// This extends the buffer by `len` bytes, all set to `value`. The `len`
    /// parameter must be a multiple of `size_of::<T>()` to ensure proper alignment.
    ///
    /// # Errors
    ///
    /// Returns `Err(CopyError)` if the backend allocator fails to perform the
    /// memory operation.
    ///
    /// # Panics
    ///
    /// - Panics if `len` is not a multiple of `size_of::<T>()`
    /// - Panics if extending by `len` bytes would exceed the buffer's capacity
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut buffer: Buffer<u32> = Buffer::with_capacity(10);
    ///
    /// // Write 12 bytes (3 u32s) of value 0xFF
    /// buffer.write_bytes(0xFF, 12).unwrap();
    /// assert_eq!(buffer.len(), 3);
    /// assert_eq!(*buffer[0], 0xFFFFFFFF);
    /// ```
    #[track_caller]
    pub fn write_bytes(&mut self, value: u8, len: usize) -> Result<(), CopyError> {
        // The panic code path was put into a cold function to not bloat the
        // call site.
        #[inline(never)]
        #[cold]
        #[track_caller]
        fn capacity_fail(dst_len: usize, len: usize, cap: usize) -> ! {
            panic!("Cannot write {len} bytes to buffer of length {dst_len} and capacity {cap}");
        }

        // The panic code path was put into a cold function to not bloat the
        // call site.
        #[inline(never)]
        #[cold]
        #[track_caller]
        fn align_fail(len: usize, size: usize) -> ! {
            panic!("Number of bytes ({len}) does not match the size of the type ({size})");
        }

        // Check that the number of bytes matches the size of the type.
        if !len.is_multiple_of(std::mem::size_of::<T>()) {
            align_fail(len, std::mem::size_of::<T>());
        }

        // Check that the buffer has enough capacity.
        if self.len() * std::mem::size_of::<T>() + len > self.capacity() * std::mem::size_of::<T>()
        {
            capacity_fail(self.len(), len, self.capacity());
        }

        // Write the bytes to the buffer.
        unsafe {
            self.buf.allocator().write_bytes(
                self.buf.ptr().add(self.len()) as *mut u8,
                value,
                len,
            )?;
        }

        // Extend the length of the buffer to include the new elements.
        self.len += len / std::mem::size_of::<T>();

        Ok(())
    }

    /// Reinterprets the buffer's elements as base field elements.
    ///
    /// This method consumes the buffer and returns a new buffer where each
    /// extension field element is reinterpreted as `D` base field elements,
    /// where `D` is the degree of the extension.
    ///
    /// # Type Parameters
    ///
    /// - `E`: The base field type
    /// - `T`: Must implement `ExtensionField<E>`
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // If T is a degree-4 extension over E
    /// let buffer: Buffer<ExtField> = buffer![ext1, ext2, ext3];
    /// let base_buffer: Buffer<BaseField> = buffer.flatten_to_base();
    /// assert_eq!(base_buffer.len(), 12); // 3 * 4 = 12
    /// ```
    pub fn flatten_to_base<E>(self) -> Buffer<E, A>
    where
        T: ExtensionField<E>,
        E: Field,
    {
        let mut buffer = ManuallyDrop::new(self);
        let (original_ptr, original_len, original_cap, allocator) =
            (buffer.as_mut_ptr(), buffer.len(), buffer.capacity(), buffer.allocator().clone());
        let ptr = original_ptr as *mut E;
        let len = original_len * T::D;
        let cap = original_cap * T::D;
        unsafe { Buffer::from_raw_parts(ptr, len, cap, allocator) }
    }
}

impl<T, A: Backend> HasBackend for Buffer<T, A> {
    type Backend = A;

    fn backend(&self) -> &Self::Backend {
        self.buf.allocator()
    }
}

impl<T> Buffer<T, CpuBackend> {
    /// Constructs a new, empty `Buffer<T>` with at least the specified capacity.
    ///
    /// This is a convenience method that uses the global CPU backend allocator.
    /// The buffer will be able to hold at least `capacity` elements without
    /// reallocating. If `capacity` is 0, the buffer will not allocate.
    ///
    /// Note that for CPU backend buffers, the capacity can grow beyond the initial
    /// value through operations like `push` or `extend_from_slice`.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity exceeds `isize::MAX` bytes.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut buffer = Buffer::with_capacity(10);
    /// assert!(buffer.capacity() >= 10);
    /// ```
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity_in(capacity, GLOBAL_CPU_BACKEND)
    }

    /// Appends an element to the back of the buffer.
    ///
    /// For CPU backend buffers, this may cause reallocation if the buffer is full.
    /// The reallocation is handled by converting to/from `Vec<T>` internally.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity exceeds `isize::MAX` bytes.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut buffer = Buffer::with_capacity(2);
    /// buffer.push(3);
    /// assert_eq!(&*buffer, &[3]);
    ///
    /// buffer.push(4);
    /// assert_eq!(&*buffer, &[3, 4]);
    ///
    /// // This will trigger reallocation
    /// buffer.push(5);
    /// assert_eq!(&*buffer, &[3, 4, 5]);
    /// assert!(buffer.capacity() >= 3);
    /// ```
    #[inline]
    pub fn push(&mut self, value: T) {
        let take_self = std::mem::take(self);
        let mut vec = Vec::from(take_self);
        vec.push(value);
        *self = Self::from(vec);
    }

    /// Removes the last element from the buffer and returns it, or `None` if empty.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut buffer = buffer![1, 2, 3];
    /// assert_eq!(buffer.pop(), Some(3));
    /// assert_eq!(&*buffer, &[1, 2]);
    /// assert_eq!(buffer.pop(), Some(2));
    /// assert_eq!(buffer.pop(), Some(1));
    /// assert_eq!(buffer.pop(), None);
    /// ```
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }

        // This is safe because we have just checked that the buffer is not empty.
        unsafe {
            let len = self.len();
            let ptr = &mut self[len - 1] as *mut _ as *mut T;
            let value = ptr.read();
            self.set_len(len - 1);
            Some(value)
        }
    }

    /// Clears the buffer, removing all values.
    ///
    /// Note that this method has no effect on the allocated capacity of the buffer.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut buffer = buffer![1, 2, 3];
    /// buffer.clear();
    /// assert!(buffer.is_empty());
    /// assert!(buffer.capacity() >= 3);
    /// ```
    #[inline]
    pub fn clear(&mut self) {
        let elems: *mut [T] = self.as_mut_slice();

        // SAFETY:
        // - `elems` comes directly from `as_mut_slice` and is therefore valid.
        // - Setting `self.len` before calling `drop_in_place` means that, if an element's `Drop`
        //   impl panics, the vector's `Drop` impl will do nothing (leaking the rest of the
        //   elements) instead of dropping some twice.
        unsafe {
            self.len = 0;
            std::ptr::drop_in_place(elems);
        }
    }

    /// Resizes the buffer in-place so that `len` is equal to `new_len`.
    ///
    /// If `new_len` is greater than `len`, the buffer is extended by the
    /// difference, with each additional slot filled with `value`.
    /// If `new_len` is less than `len`, the buffer is simply truncated.
    ///
    /// This method may trigger reallocation if `new_len` exceeds the current capacity.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut buffer = buffer![1, 2, 3];
    /// buffer.resize(5, 0);
    /// assert_eq!(&*buffer, &[1, 2, 3, 0, 0]);
    ///
    /// buffer.resize(2, 0);
    /// assert_eq!(&*buffer, &[1, 2]);
    /// ```
    #[inline]
    pub fn resize(&mut self, new_len: usize, value: T)
    where
        T: Copy,
    {
        let owned_self = std::mem::take(self);
        let mut vec = Vec::from(owned_self);
        vec.resize(new_len, value);
        *self = Self::from(vec);
    }

    /// Extends the buffer with the contents of the given slice.
    ///
    /// This is a specialized version for CPU backend that can trigger reallocation
    /// if needed to accommodate the new elements.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut buffer = buffer![1, 2, 3];
    /// buffer.extend_from_slice(&[4, 5, 6]);
    /// assert_eq!(&*buffer, &[1, 2, 3, 4, 5, 6]);
    /// ```
    #[inline]
    pub fn extend_from_slice(&mut self, slice: &[T]) {
        // Check to see if capacity needs to be increased.
        if self.len() + slice.len() > self.capacity() {
            let additional_capacity = self.len() + slice.len() - self.capacity();
            let owned_self = std::mem::take(self);
            let mut vec = Vec::from(owned_self);
            vec.reserve(vec.capacity() + additional_capacity);
            *self = Self::from(vec);
            assert!(self.capacity() >= self.len() + slice.len());
        }

        self.extend_from_host_slice(slice).unwrap()
    }

    /// Converts the buffer into a `Vec<T>`.
    ///
    /// This consumes the buffer and transfers ownership of its data to a standard
    /// `Vec`. This is a zero-cost operation as the underlying memory layout is
    /// compatible.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let buffer = buffer![1, 2, 3];
    /// let vec = buffer.into_vec();
    /// assert_eq!(vec, vec![1, 2, 3]);
    /// ```
    #[inline]
    pub fn into_vec(self) -> Vec<T> {
        self.into()
    }

    /// Returns a slice containing the entire buffer.
    ///
    /// Equivalent to `&buffer[..]`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let buffer = buffer![1, 2, 3];
    /// assert_eq!(buffer.as_slice(), &[1, 2, 3]);
    /// ```
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self[..]
    }

    /// Returns a mutable slice containing the entire buffer.
    ///
    /// Equivalent to `&mut buffer[..]`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut buffer = buffer![1, 2, 3];
    /// buffer.as_mut_slice()[0] = 7;
    /// assert_eq!(&*buffer, &[7, 2, 3]);
    /// ```
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self[..]
    }

    /// Returns the remaining spare capacity of the buffer as a slice of `MaybeUninit<T>`.
    ///
    /// The returned slice can be used to fill the buffer with data before marking
    /// the data as initialized using [`set_len`].
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut buffer = Buffer::with_capacity(10);
    /// buffer.push(0);
    /// buffer.push(1);
    ///
    /// let spare = buffer.spare_capacity_mut();
    /// assert_eq!(spare.len(), 8);
    ///
    /// // Initialize the spare capacity
    /// for i in 0..4 {
    ///     spare[i].write(i as i32 + 2);
    /// }
    ///
    /// unsafe {
    ///     buffer.set_len(6);
    /// }
    /// assert_eq!(&*buffer, &[0, 1, 2, 3, 4, 5]);
    /// ```
    ///
    /// [`set_len`]: Buffer::set_len
    pub fn spare_capacity_mut(&mut self) -> &mut [MaybeUninit<T>] {
        let mut vec = ManuallyDrop::new(unsafe {
            Vec::from_raw_parts(self.as_mut_ptr(), self.len(), self.capacity())
        });
        let slice = vec.spare_capacity_mut();
        let len = slice.len();
        let ptr = slice.as_mut_ptr();
        unsafe { std::slice::from_raw_parts_mut(ptr, len) }
    }

    /// Inserts an element at position `index`, shifting all elements after it to the right.
    ///
    /// This operation may trigger reallocation if the buffer is at capacity.
    ///
    /// # Panics
    ///
    /// Panics if `index > len`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut buffer = buffer![1, 2, 3];
    /// buffer.insert(1, 4);
    /// assert_eq!(&*buffer, &[1, 4, 2, 3]);
    /// buffer.insert(4, 5);
    /// assert_eq!(&*buffer, &[1, 4, 2, 3, 5]);
    /// ```
    #[inline]
    pub fn insert(&mut self, index: usize, value: T) {
        let take_self = std::mem::take(self);
        let mut vec = Vec::from(take_self);
        vec.insert(index, value);
        *self = Self::from(vec);
    }

    /// Reinterprets the buffer's base field elements as extension field elements.
    ///
    /// This method consumes the buffer and returns a new buffer where every `D`
    /// base field elements are reinterpreted as one extension field element,
    /// where `D` is the degree of the extension.
    ///
    /// # Type Parameters
    ///
    /// - `T`: The base field type
    /// - `E`: Must implement `ExtensionField<T>`
    ///
    /// # Panics
    ///
    /// Panics if the buffer length is not divisible by the extension degree.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // If E is a degree-4 extension over T
    /// let buffer: Buffer<BaseField> = buffer![b1, b2, b3, b4, b5, b6, b7, b8];
    /// let ext_buffer: Buffer<ExtField> = buffer.into_extension();
    /// assert_eq!(ext_buffer.len(), 2); // 8 / 4 = 2
    /// ```
    pub fn into_extension<E>(self) -> Buffer<E, CpuBackend>
    where
        T: Field,
        E: ExtensionField<T>,
    {
        self.into_vec().chunks_exact(E::D).map(E::from_base_slice).collect()
    }
}

impl<T> From<Vec<T>> for Buffer<T, CpuBackend> {
    /// Creates a buffer from a `Vec<T>`.
    ///
    /// This is a zero-cost conversion that takes ownership of the vector's
    /// allocated memory.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let vec = vec![1, 2, 3, 4];
    /// let buffer = Buffer::from(vec);
    /// assert_eq!(&*buffer, &[1, 2, 3, 4]);
    /// ```
    fn from(value: Vec<T>) -> Self {
        unsafe {
            let mut vec = ManuallyDrop::new(value);
            Buffer::from_raw_parts(vec.as_mut_ptr(), vec.len(), vec.capacity(), GLOBAL_CPU_BACKEND)
        }
    }
}

impl<T> Default for Buffer<T, CpuBackend> {
    /// Creates an empty buffer.
    ///
    /// Equivalent to `Buffer::with_capacity(0)`.
    #[inline]
    fn default() -> Self {
        Self::with_capacity(0)
    }
}

impl<T> From<Buffer<T, CpuBackend>> for Vec<T> {
    /// Converts a buffer into a `Vec<T>`.
    ///
    /// This is a zero-cost conversion that transfers ownership of the buffer's
    /// allocated memory to the vector.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let buffer = buffer![1, 2, 3];
    /// let vec = Vec::from(buffer);
    /// assert_eq!(vec, vec![1, 2, 3]);
    /// ```
    fn from(value: Buffer<T, CpuBackend>) -> Self {
        let mut self_undropped = ManuallyDrop::new(value);
        unsafe {
            Vec::from_raw_parts(
                self_undropped.as_mut_ptr(),
                self_undropped.len(),
                self_undropped.capacity(),
            )
        }
    }
}

impl<T> FromIterator<T> for Buffer<T, CpuBackend> {
    /// Creates a buffer from an iterator.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let buffer: Buffer<_> = (0..5).collect();
    /// assert_eq!(&*buffer, &[0, 1, 2, 3, 4]);
    ///
    /// let buffer: Buffer<_> = vec![1, 2, 3].into_iter().collect();
    /// assert_eq!(&*buffer, &[1, 2, 3]);
    /// ```
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let vec: Vec<T> = iter.into_iter().collect();
        Self::from(vec)
    }
}

/// Creates a [`Buffer`] containing the arguments.
///
/// `buffer!` allows creating buffers using the same syntax as the `vec!` macro.
/// It simply creates a `Vec` and converts it to a `Buffer`.
///
/// # Examples
///
/// ```rust,ignore
/// let buffer = buffer![1, 2, 3];
/// assert_eq!(&*buffer, &[1, 2, 3]);
///
/// let buffer = buffer![0; 5];
/// assert_eq!(&*buffer, &[0, 0, 0, 0, 0]);
/// ```
///
/// [`Buffer`]: crate::Buffer
#[macro_export]
macro_rules! buffer {
    ($($x:expr),*) => {
       $crate::Buffer::from(vec![$($x),*])
    };
}

macro_rules! impl_index {
    ($($t:ty)*) => {
        $(
            impl<T, A: Backend> Index<$t> for Buffer<T, A>
            {
                type Output = Slice<T, A>;

                fn index(&self, index: $t) -> &Slice<T, A> {
                    unsafe {
                        Slice::from_slice(
                         std::slice::from_raw_parts(self.as_ptr(), self.len).index(index)
                    )
                  }
                }
            }

            impl<T, A: Backend> IndexMut<$t> for Buffer<T, A>
            {
                fn index_mut(&mut self, index: $t) -> &mut Slice<T, A> {
                    unsafe {
                        Slice::from_slice_mut(
                            std::slice::from_raw_parts_mut(self.as_mut_ptr(), self.len).index_mut(index)
                        )
                    }
                }
            }
        )*
    }
}

impl_index! {
    Range<usize>
    RangeFull
    RangeFrom<usize>
    RangeInclusive<usize>
    RangeTo<usize>
    RangeToInclusive<usize>
}

impl<T, A: Backend> Deref for Buffer<T, A> {
    type Target = Slice<T, A>;

    fn deref(&self) -> &Self::Target {
        &self[..]
    }
}

impl<T, A: Backend> DerefMut for Buffer<T, A> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self[..]
    }
}

impl<T, A: Backend> Index<usize> for Buffer<T, A> {
    type Output = Init<T, A>;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self[..][index]
    }
}

impl<T, A: Backend> IndexMut<usize> for Buffer<T, A> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self[..][index]
    }
}

impl<T, A: Backend> Clone for Buffer<T, A> {
    /// Returns a copy of the buffer.
    ///
    /// This allocates a new buffer with the same capacity as `self` and copies
    /// all elements using the backend's `copy_nonoverlapping` operation.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let buffer1 = buffer![1, 2, 3];
    /// let buffer2 = buffer1.clone();
    /// assert_eq!(&*buffer1, &*buffer2);
    /// ```
    #[inline]
    fn clone(&self) -> Self {
        let mut cloned = Self::with_capacity_in(self.len(), self.allocator().clone());
        let layout = Layout::array::<T>(self.len()).unwrap();
        unsafe {
            self.buf
                .allocator()
                .copy_nonoverlapping(
                    self.as_ptr() as *const u8,
                    cloned.as_mut_ptr() as *mut u8,
                    layout.size(),
                    CopyDirection::DeviceToDevice,
                )
                .unwrap();
            cloned.set_len(self.len());
        }
        cloned
    }
}

impl<T: PartialEq> PartialEq for Buffer<T, CpuBackend> {
    /// Tests for equality between two buffers.
    ///
    /// Two buffers are considered equal if the underlying slices are equal, i.e. they have the same
    /// length and all corresponding elements are equal. Capacity is not considered.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let buffer1 = buffer![1, 2, 3];
    /// let buffer2 = buffer![1, 2, 3];
    /// assert_eq!(buffer1, buffer2);
    ///
    /// let buffer3 = buffer![1, 2, 4];
    /// assert_ne!(buffer1, buffer3);
    /// ```
    fn eq(&self, other: &Self) -> bool {
        self[..] == other[..]
    }
}

impl<T: Eq> Eq for Buffer<T, CpuBackend> {}

impl<T: Serialize> Serialize for Buffer<T, CpuBackend> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_slice().serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Buffer<T, CpuBackend> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let vec: Vec<T> = Vec::deserialize(deserializer)?;
        Ok(Buffer::from(vec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer() {
        let mut buffer = Buffer::<u32>::with_capacity(10);
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.capacity(), 10);

        buffer.push(1);
        buffer.push(2);
        buffer.push(3);
        assert_eq!(buffer.len(), 3);

        let as_slice: &[u32] = &buffer[..];
        assert_eq!(as_slice, &[1, 2, 3]);

        let val = *buffer[0];
        assert_eq!(val, 1);

        let val = *buffer[1];
        assert_eq!(val, 2);

        let val = *buffer[2];
        assert_eq!(val, 3);

        let value = buffer.pop().unwrap();
        assert_eq!(value, 3);
        assert_eq!(buffer.len(), 2);

        buffer.extend_from_slice(&[4, 5, 6]);
        let host_vec = Vec::from(buffer);
        assert_eq!(host_vec, [1, 2, 4, 5, 6]);

        // Test the host_buffer!() macro
        let buffer = buffer![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(buffer.len(), 10);
        assert_eq!(buffer.capacity(), 10);
        assert_eq!(*buffer[0], 1);
        assert_eq!(*buffer[1], 2);
        assert_eq!(*buffer[2], 3);
        assert_eq!(*buffer[3], 4);
        assert_eq!(*buffer[4], 5);
        assert_eq!(*buffer[5], 6);
        assert_eq!(*buffer[6], 7);
        assert_eq!(*buffer[7], 8);
        assert_eq!(*buffer[8], 9);
        assert_eq!(*buffer[9], 10);

        let mut buffer = buffer![1, 2, 3, 4, 5, 6, 7, 8, 9];
        buffer.insert(0, 0);
        assert_eq!(buffer.len(), 10);
        assert_eq!(*buffer[0], 0);
        assert_eq!(*buffer[1], 1);
        assert_eq!(*buffer[2], 2);
        assert_eq!(*buffer[3], 3);
        assert_eq!(*buffer[4], 4);
        buffer.insert(4, 4);
        assert_eq!(buffer.len(), 11);
        assert_eq!(*buffer[4], 4);
        assert_eq!(*buffer[5], 4);
    }
}
