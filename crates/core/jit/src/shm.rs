//! This module contains shared memory data structures written by Gemini 3.

use libc::{
    c_uint, c_void, ftruncate, madvise, sem_close, sem_open, sem_post, sem_t, sem_unlink, sem_wait,
    shm_open, shm_unlink, MADV_FREE, O_CREAT, O_RDWR, S_IRUSR, S_IWUSR,
};
use memmap2::{Mmap, MmapMut};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Error};
use std::ops::{Deref, DerefMut};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// POSIX Shared Memory Ring Buffer
//
// Written by Gemini 3
//
// A high-performance, cross-platform (Linux & macOS), Single-Producer Single-Consumer (SPSC)
// ring buffer using POSIX Shared Memory and Named Semaphores.
//
// Features:
// * Huge Page Optimized: Aligns slots to 2MB and uses MADV_HUGEPAGE (Linux) for performance.
// * Lazy Allocation: Uses sparse files; physical RAM is only consumed upon writing.
// * RAII Safety: Automatic resource cleanup (unlink) and data commit on drop.
// * Blocking API: 0% CPU usage when waiting for data or space.
// * Parallel Access: Decouples reservation from completion, allowing multiple chunks to be held at once.

// --- CONFIGURATION ---
const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;
const HEADER_SIZE: usize = HUGE_PAGE_SIZE;

#[repr(C)]
struct RingHeader {
    write_idx: AtomicUsize,

    // "Safe" index (Oldest slot still in use). Producer checks this.
    read_idx: AtomicUsize,

    // "Next" index (Next slot to dispense). Consumer checks this.
    reserved_idx: AtomicUsize,

    capacity: usize,
    slot_size: usize,
    finished: AtomicUsize,
}

struct PosixSemaphore {
    sem: *mut sem_t,
}
unsafe impl Send for PosixSemaphore {}
unsafe impl Sync for PosixSemaphore {}

impl PosixSemaphore {
    fn create(name: &str, value: u32) -> std::io::Result<Self> {
        let c_name = CString::new(name).unwrap();
        unsafe {
            let sem = sem_open(c_name.as_ptr(), O_CREAT, 0o644, value);
            if sem == libc::SEM_FAILED {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self { sem })
        }
    }
    fn wait(&self) {
        unsafe {
            sem_wait(self.sem);
        }
    }
    fn post(&self) {
        unsafe {
            sem_post(self.sem);
        }
    }
}
impl Drop for PosixSemaphore {
    fn drop(&mut self) {
        unsafe {
            sem_close(self.sem);
        }
    }
}

struct InnerRing {
    _file: File,
    _mmap: MmapMut,
    header: *mut RingHeader,
    data_start: *mut u8,
    sem_filled: PosixSemaphore,
    sem_empty: PosixSemaphore,
    name: String,
    is_owner: bool,

    // Reorder Buffer: Stores indices that are finished but waiting for sequential gap to close.
    pending_completions: Mutex<BinaryHeap<Reverse<usize>>>,
}

unsafe impl Send for InnerRing {}
unsafe impl Sync for InnerRing {}

impl Drop for InnerRing {
    fn drop(&mut self) {
        if self.is_owner {
            let c_name = CString::new(self.name.clone()).unwrap();
            let c_fill = CString::new(format!("{}_filled", self.name)).unwrap();
            let c_empty = CString::new(format!("{}_empty", self.name)).unwrap();
            unsafe {
                shm_unlink(c_name.as_ptr());
                sem_unlink(c_fill.as_ptr());
                sem_unlink(c_empty.as_ptr());
            }
        }
    }
}

/// A shared memory based, ring-buffer structure. It provides trace buffers for child
/// native executor process to write, and for parent SP1 process to read.
#[derive(Clone)]
pub struct ShmTraceRing {
    inner: Arc<InnerRing>,
}

// --- GUARDS ---

pub struct ProducerGuard {
    inner: Arc<InnerRing>,
    data_ptr: *mut u8,
    len: usize,
}
unsafe impl Send for ProducerGuard {}
unsafe impl Sync for ProducerGuard {}

impl Drop for ProducerGuard {
    fn drop(&mut self) {
        unsafe {
            (*self.inner.header).write_idx.fetch_add(1, Ordering::Release);
        }
        self.inner.sem_filled.post();
    }
}
impl Deref for ProducerGuard {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.data_ptr, self.len) }
    }
}
impl DerefMut for ProducerGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::slice::from_raw_parts_mut(self.data_ptr, self.len) }
    }
}

pub struct ConsumerGuard {
    inner: Arc<InnerRing>,
    data_ptr: *const u8,
    len: usize,
    index: usize,
}
unsafe impl Send for ConsumerGuard {}
unsafe impl Sync for ConsumerGuard {}

impl Drop for ConsumerGuard {
    fn drop(&mut self) {
        self.inner.complete_read(self.index);
    }
}
impl Deref for ConsumerGuard {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.data_ptr, self.len) }
    }
}

// --- LOGIC ---

impl InnerRing {
    fn complete_read(&self, completed_idx: usize) {
        let mut heap = self.pending_completions.lock().unwrap();

        // Push completion to heap
        heap.push(Reverse(completed_idx));

        let mut current_read = unsafe { (*self.header).read_idx.load(Ordering::Acquire) };

        // Drain sequential items
        while let Some(Reverse(min_idx)) = heap.peek() {
            if *min_idx == current_read {
                heap.pop();
                unsafe {
                    (*self.header).read_idx.fetch_add(1, Ordering::Release);
                }
                self.sem_empty.post();
                current_read += 1;
            } else {
                break;
            }
        }
    }
}

impl ShmTraceRing {
    // Create: accepts logical ID, creates file "/{id}_t"
    pub fn create(id: &str, capacity: usize, slot_size: usize) -> std::io::Result<Self> {
        Self::init(id, capacity, slot_size, true)
    }

    // Open: accepts logical ID, opens file "/{id}_t"
    pub fn open(id: &str, capacity: usize, slot_size: usize) -> std::io::Result<Self> {
        Self::init(id, capacity, slot_size, false)
    }

    fn init(id: &str, capacity: usize, slot_size: usize, is_owner: bool) -> std::io::Result<Self> {
        // Force 2MB Alignment
        let aligned_size = (slot_size + HUGE_PAGE_SIZE - 1) & !(HUGE_PAGE_SIZE - 1);

        // Logic: ID -> Name conversion with suffix
        let base_name =
            if id.starts_with('/') { format!("{}_t", id) } else { format!("/{}_t", id) };

        let c_name = CString::new(base_name.clone()).unwrap();
        let total_size = HEADER_SIZE + (capacity * aligned_size);

        let fd = unsafe {
            if is_owner {
                shm_unlink(c_name.as_ptr());
                shm_open(c_name.as_ptr(), O_CREAT | O_RDWR, (S_IRUSR | S_IWUSR) as c_uint)
            } else {
                shm_open(c_name.as_ptr(), O_RDWR, 0)
            }
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        if is_owner {
            unsafe { ftruncate(fd, total_size as libc::off_t) };
        }

        let file = unsafe { File::from_raw_fd(fd) };
        let mut mmap = unsafe { MmapMut::map_mut(&file)? };

        #[cfg(target_os = "linux")]
        unsafe {
            libc::madvise(mmap.as_mut_ptr() as *mut c_void, mmap.len(), libc::MADV_HUGEPAGE);
        }

        let header = mmap.as_ptr() as *mut RingHeader;
        let data_start = unsafe { mmap.as_mut_ptr().add(HEADER_SIZE) };

        if is_owner {
            unsafe {
                (*header).capacity = capacity;
                (*header).slot_size = aligned_size;
                (*header).write_idx.store(0, Ordering::Release);
                (*header).read_idx.store(0, Ordering::Release);
                (*header).reserved_idx.store(0, Ordering::Release);
                (*header).finished.store(0, Ordering::Release);
            }
        }

        let sem_filled_name = format!("{}_filled", base_name);
        let sem_empty_name = format!("{}_empty", base_name);

        if is_owner {
            let c_fill = CString::new(sem_filled_name.clone()).unwrap();
            let c_empty = CString::new(sem_empty_name.clone()).unwrap();
            unsafe {
                sem_unlink(c_fill.as_ptr());
                sem_unlink(c_empty.as_ptr());
            }
        }

        let sem_filled = PosixSemaphore::create(&sem_filled_name, 0)?;
        let initial_empty = if is_owner { capacity as u32 } else { 0 };
        let sem_empty = PosixSemaphore::create(&sem_empty_name, initial_empty)?;

        // Crash Recovery: Sync reserved_idx if consumer restarts
        if !is_owner {
            unsafe {
                let committed = (*header).read_idx.load(Ordering::Acquire);
                let reserved = (*header).reserved_idx.load(Ordering::Acquire);
                if reserved > committed {
                    (*header).reserved_idx.store(committed, Ordering::Release);
                }
            }
        }

        Ok(Self {
            inner: Arc::new(InnerRing {
                _file: file,
                _mmap: mmap,
                header,
                data_start,
                sem_filled,
                sem_empty,
                name: base_name,
                is_owner,
                pending_completions: Mutex::new(BinaryHeap::new()),
            }),
        })
    }

    pub fn acquire(&self) -> ProducerGuard {
        self.inner.sem_empty.wait();

        let (w, _, cap, size) = unsafe { self.load_state() };
        let slot_idx = w % cap;
        let offset = slot_idx * size;

        unsafe {
            let ptr = self.inner.data_start.add(offset);
            madvise(ptr as *mut c_void, size, MADV_FREE);
            ProducerGuard { inner: self.inner.clone(), data_ptr: ptr, len: size }
        }
    }

    pub fn mark_finished(&self) {
        unsafe {
            (*self.inner.header).finished.store(1, Ordering::Release);
        }
        self.inner.sem_filled.post();
    }

    pub fn access(&self) -> Option<ConsumerGuard> {
        self.inner.sem_filled.wait();

        unsafe {
            let h = self.inner.header;

            // 1. Peek at indices to check for EOS or data availability
            let w = (*h).write_idx.load(Ordering::Acquire);
            let current_reserved = (*h).reserved_idx.load(Ordering::Acquire);

            if w == current_reserved {
                if (*h).finished.load(Ordering::Acquire) == 1 {
                    self.inner.sem_filled.post(); // Wake other consumers
                    return None;
                }
                // Spurious wake or race condition, retry
                return self.access();
            }

            // 2. Claim unique slot index
            let my_idx = (*h).reserved_idx.fetch_add(1, Ordering::Release);

            let cap = (*h).capacity;
            let size = (*h).slot_size;
            let slot_idx = my_idx % cap;
            let offset = slot_idx * size;

            let ptr = self.inner.data_start.add(offset);

            Some(ConsumerGuard {
                inner: self.inner.clone(),
                data_ptr: ptr,
                len: size,
                index: my_idx,
            })
        }
    }

    unsafe fn load_state(&self) -> (usize, usize, usize, usize) {
        let h = self.inner.header;
        (
            (*h).write_idx.load(Ordering::Relaxed),
            (*h).read_idx.load(Ordering::Relaxed),
            (*h).capacity,
            (*h).slot_size,
        )
    }
}

// # Simple POSIX Shared Memory Wrapper
//
// This module provides a simplified, RAII-compliant abstraction over POSIX shared memory
// (`shm_open`) and memory mapping (`mmap`), utilizing `libc` for system calls and
// `memmap2` for safe memory handling.
//
// ## Design & Modes
// The `ShmMemory` struct supports two distinct lifecycles requested for this implementation:
//
// 1.  **Creation (Read-Only Map):**
//     * Creates the shared memory object (`O_CREAT`).
//     * Sets the size via `ftruncate`.
//     * Maps the memory into the process as **Read-Only**.
//     * *Cleanup:* Unlinks (deletes) the shared memory name upon Drop.
//
// 2.  **Connection (Read-Write Map):**
//     * Opens an existing shared memory object.
//     * Maps the memory into the process as **Read-Write**.
//     * *Cleanup:* Closes the file descriptor but leaves the shared memory name intact.
//
// ## Traits
// * **`Deref`**: Access underlying memory as `&[u8]`.
// * **`DerefMut`**: Access underlying memory as `&mut [u8]` (Panics if map is Read-Only).
// * **`AsRawFd`**: Exposes the underlying file descriptor for polling or other syscalls.

/// An enum to hold either a Read-Only or Read-Write memory map.
#[derive(Debug)]
enum InnerMap {
    ReadOnly(Mmap),
    ReadWrite(MmapMut),
}

/// A handle to a POSIX shared memory object.
///
/// This struct manages the file descriptor and the memory map.
/// It implements RAII: dropping this struct closes the FD and, if it was
/// the creator, unlinks the shared memory name.
pub struct ShmMemory {
    /// We keep the name to unlink it later if needed.
    name: String,
    /// The underlying File object (owns the FD).
    file: File,
    /// The actual memory mapping (Safe wrapper around the raw pointer).
    map: InnerMap,
    /// If true, we execute `shm_unlink` on Drop.
    should_unlink: bool,
}

impl ShmMemory {
    /// **Way 1: Creation.**
    /// Creates a new shm file, sets its size, and maps it as **Read-Only**.
    ///
    /// Internally opens with `O_RDWR` to allow `ftruncate` (setting size),
    /// but restricts the process memory map to Read-Only.
    pub fn create_readonly(id: &str, size: usize) -> io::Result<Self> {
        let (file, name, _) = Self::open_libc(id, libc::O_CREAT | libc::O_RDWR, size)?;

        // Safety: We just created the file, so mapping it is valid.
        let map = unsafe { Mmap::map(&file)? };

        Ok(Self {
            name,
            file,
            map: InnerMap::ReadOnly(map),
            should_unlink: true, // Creator assumes responsibility for cleanup
        })
    }

    /// **Way 2: Connection.**
    /// Opens an existing shm file and maps it as **Read-Write**.
    ///
    /// Requires the file to already exist.
    pub fn open_readwrite(id: &str) -> io::Result<Self> {
        // Size 0 implies "do not truncate/resize".
        let (file, name, _) = Self::open_libc(id, libc::O_RDWR, 0)?;

        // Safety: We opened with O_RDWR, so mapping as MmapMut is valid.
        let map = unsafe { MmapMut::map_mut(&file)? };

        Ok(Self {
            name,
            file,
            map: InnerMap::ReadWrite(map),
            should_unlink: false, // Opener does not destroy the resource
        })
    }

    /// Helper to handle the libc boilerplate safely.
    /// Returns the File and a boolean indicating if it was just created.
    fn open_libc(id: &str, flags: libc::c_int, size: usize) -> io::Result<(File, String, bool)> {
        let name = format!("{}_m", id);
        let clean_name = if name.starts_with('/') { name } else { format!("/{}", name) };
        let c_id = CString::new(clean_name.as_str())
            .map_err(|e| Error::new(io::ErrorKind::InvalidInput, e))?;

        unsafe {
            let owner_flag = if flags & libc::O_CREAT != 0 { S_IRUSR | S_IWUSR } else { 0 };
            // 1. shm_open
            // Mode 0o666 = Read/Write for everyone.
            let fd = shm_open(c_id.as_ptr(), flags, owner_flag as c_uint);
            if fd < 0 {
                return Err(Error::last_os_error());
            }

            // Wrap in File immediately for RAII closing of the FD.
            let file = File::from_raw_fd(fd);

            // 2. If size > 0, we must ftruncate to ensure memory is allocated.
            if size > 0 {
                let ret = libc::ftruncate(fd, size as libc::off_t);
                if ret < 0 {
                    return Err(Error::last_os_error());
                }
            }

            let created = (flags & libc::O_CREAT) != 0;
            Ok((file, clean_name, created))
        }
    }

    /// Manually flags this instance to NOT unlink on drop.
    /// Useful if you want the shared memory to persist after the process exits.
    pub fn keep_on_drop(&mut self) {
        self.should_unlink = false;
    }
}

// --- Traits Implementation ---

impl AsRawFd for ShmMemory {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Deref for ShmMemory {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match &self.map {
            InnerMap::ReadOnly(m) => m.as_ref(),
            InnerMap::ReadWrite(m) => m.as_ref(),
        }
    }
}

impl DerefMut for ShmMemory {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut self.map {
            InnerMap::ReadOnly(_) => {
                // Panic ensures safety: we cannot give mutable access to read-only memory.
                panic!("ShmMemory Error: Attempted to DerefMut on a Read-Only handle");
            }
            InnerMap::ReadWrite(m) => m.as_mut(),
        }
    }
}

impl Drop for ShmMemory {
    fn drop(&mut self) {
        if self.should_unlink {
            // Ignore errors here (e.g., if it was already unlinked externally)
            if let Ok(c_name) = CString::new(self.name.as_str()) {
                unsafe {
                    libc::shm_unlink(c_name.as_ptr());
                }
            }
        }
        // self.file drops here, closing the FD automatically.
    }
}
