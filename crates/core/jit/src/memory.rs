use crate::{shm::ShmMemory, JitMemory, JitResetableMemory};
use memmap2::{MmapMut, MmapOptions};
use std::{
    fs::File,
    io,
    ops::{Deref, DerefMut},
    os::fd::AsRawFd,
};

/// JIT memory fulfilled using anonymous memory
pub struct AnonymousMemory {
    pub mem_fd: File,
    pub memory: MmapMut,
}

impl AsRawFd for AnonymousMemory {
    fn as_raw_fd(&self) -> i32 {
        self.mem_fd.as_raw_fd()
    }
}

impl Deref for AnonymousMemory {
    type Target = [u8];

    fn deref(&self) -> &<Self as Deref>::Target {
        self.memory.deref()
    }
}

impl DerefMut for AnonymousMemory {
    fn deref_mut(&mut self) -> &mut <Self as Deref>::Target {
        self.memory.deref_mut()
    }
}

impl JitMemory for AnonymousMemory {
    fn new(memory_size: usize) -> Self {
        let file = create_anonymous_file(memory_size);

        let memory = unsafe {
            MmapOptions::new().no_reserve_swap().map_mut(&file).expect("Failed to call mmap")
        };

        Self { mem_fd: file, memory }
    }
}

impl JitResetableMemory for AnonymousMemory {
    fn reset(&mut self) {
        // Store the original size of the memory.
        let memory_size = self.memory.len();

        // Create a new memfd for the backing memory.
        self.mem_fd = create_anonymous_file(memory_size);

        self.memory = unsafe {
            MmapOptions::new()
                .no_reserve_swap()
                .map_mut(&self.mem_fd)
                .expect("Failed to map memory")
        };
    }
}

#[cfg(target_os = "linux")]
fn create_anonymous_file(size: usize) -> File {
    let fd = memfd::MemfdOptions::default()
        .create(uuid::Uuid::new_v4().to_string())
        .expect("Failed to create jit memory");
    let file = fd.into_file();
    file.set_len(size as u64).expect("Faile to set length for jit memory");
    file
}

#[cfg(target_os = "macos")]
fn create_anonymous_file(size: usize) -> File {
    use libc::{c_char, c_uint, ftruncate, shm_open, O_CREAT, O_RDWR, S_IRUSR, S_IWUSR};
    use std::io;
    use std::os::fd::FromRawFd;

    // This is missing in libc, we have to manually define it.
    const SHM_ANON: *const c_char = -1isize as *const c_char;

    let fd = unsafe { shm_open(SHM_ANON, O_RDWR | O_CREAT, (S_IRUSR | S_IWUSR) as c_uint) };
    if fd < 0 {
        panic!("Error creating anonymous memory file: {}", io::Error::last_os_error());
    }

    let res = unsafe { ftruncate(fd, size as _) };
    if res != 0 {
        panic!("Error setting file size: {}", io::Error::last_os_error());
    }

    unsafe { File::from_raw_fd(fd) }
}

/// JIT memory fulfilled using shared memory
pub struct SharedMemory {
    handle: Option<ShmMemory>,
}

impl SharedMemory {
    pub fn create_readonly(id: &str, memory_size: usize) -> io::Result<Self> {
        Ok(Self { handle: Some(ShmMemory::create_readonly(id, memory_size)?) })
    }

    pub fn open_readwrite(&mut self, id: &str) -> io::Result<()> {
        self.handle = Some(ShmMemory::open_readwrite(id)?);
        Ok(())
    }
}

impl AsRawFd for SharedMemory {
    fn as_raw_fd(&self) -> i32 {
        self.handle.as_ref().unwrap().as_raw_fd()
    }
}

impl Deref for SharedMemory {
    type Target = [u8];

    fn deref(&self) -> &<Self as Deref>::Target {
        self.handle.as_ref().unwrap().deref()
    }
}

impl DerefMut for SharedMemory {
    fn deref_mut(&mut self) -> &mut <Self as Deref>::Target {
        self.handle.as_mut().unwrap().deref_mut()
    }
}

impl JitMemory for SharedMemory {
    fn new(_memory_size: usize) -> Self {
        Self { handle: None }
    }
}
