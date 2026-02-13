use memmap2::{Mmap, MmapMut};
use sp1_jit::{MemValue, TraceChunkHeader};

/// A buffer to build a valid [`sp1_jit::TraceChunk`].
///
/// # SAFETY
///
/// - The caller must ensure **exlsuive access** to whatever method they're calling. ie: there
///   should be no conncurent calls to the same method.
///
/// - [`TraceChunkHeader`]s layout is stable and safely transmutable.
///
/// - If an argument is passed by a refrence, it must be a valid refrence to read from.
pub(super) struct TraceChunkBuffer {
    inner: MmapMut,
}

impl TraceChunkBuffer {
    /// Creates a new trace chunk buffer.
    ///
    /// # Panics
    ///
    /// - If the size is less than the size of [`TraceChunkHeader`].
    pub fn new(size: usize) -> Self {
        assert!(
            size >= std::mem::size_of::<TraceChunkHeader>(),
            "Trace chunk buffer size must be at least the size of the header"
        );

        Self { inner: MmapMut::map_anon(size).expect("Failed to create trace buf mmap") }
    }

    /// Writes the start registers to the header.
    ///
    /// # SAFETY
    ///
    /// See the safety section of [`TraceChunkBuffer`].
    pub unsafe fn write_start_registers(&self, start_registers: &[u64; 32]) {
        unsafe {
            std::ptr::copy_nonoverlapping(
                start_registers.as_ptr().cast::<u8>(),
                self.as_mut_ptr().add(std::mem::offset_of!(TraceChunkHeader, start_registers)),
                std::mem::size_of::<[u64; 32]>(),
            );
        }
    }

    /// Writes the pc start to the header.
    ///
    /// # SAFETY
    ///
    /// See the safety section of [`TraceChunkBuffer`].
    pub unsafe fn write_pc_start(&self, pc_start: u64) {
        unsafe {
            std::ptr::write_unaligned(
                self.as_mut_ptr()
                    .add(std::mem::offset_of!(TraceChunkHeader, pc_start))
                    .cast::<u64>(),
                pc_start,
            );
        }
    }

    /// Writes the clk start to the header.
    ///
    /// # SAFETY
    ///
    /// See the safety section of [`TraceChunkBuffer`].
    pub unsafe fn write_clk_start(&self, clk_start: u64) {
        unsafe {
            std::ptr::write_unaligned(
                self.as_mut_ptr()
                    .add(std::mem::offset_of!(TraceChunkHeader, clk_start))
                    .cast::<u64>(),
                clk_start,
            );
        }
    }

    /// Writes the clk end to the header.
    ///
    /// # SAFETY
    ///
    /// See the safety section of [`TraceChunkBuffer`].
    pub unsafe fn write_clk_end(&self, clk_end: u64) {
        unsafe {
            std::ptr::write_unaligned(
                self.as_mut_ptr()
                    .add(std::mem::offset_of!(TraceChunkHeader, clk_end))
                    .cast::<u64>(),
                clk_end,
            );
        }
    }

    /// Writes the memory reads to the buffer.
    ///
    /// # SAFETY
    ///
    /// See the safety section of [`TraceChunkBuffer`].
    ///
    /// - The caller must ensure that the buffer has enough space to write the values.
    pub unsafe fn extend(&self, values: &[MemValue]) {
        // Load the current `num_mem_reads``
        let num_mem_reads = std::ptr::read_unaligned(
            self.as_mut_ptr().add(std::mem::offset_of!(TraceChunkHeader, num_mem_reads))
                as *const u64,
        );
        // Add the count
        let new_num_mem_reads =
            num_mem_reads.checked_add(values.len() as u64).expect("Num mem reads too large");

        assert!(
            new_num_mem_reads * std::mem::size_of::<MemValue>() as u64
                <= self.inner.len() as u64 - std::mem::size_of::<TraceChunkHeader>() as u64,
            "Num mem reads ({new_num_mem_reads}) would exceed buffer capacity of {} entries",
            (self.inner.len() - std::mem::size_of::<TraceChunkHeader>())
                / std::mem::size_of::<MemValue>()
        );

        // Write the new `num_mem_reads`
        std::ptr::write_unaligned(
            self.as_mut_ptr()
                .add(std::mem::offset_of!(TraceChunkHeader, num_mem_reads))
                .cast::<u64>(),
            new_num_mem_reads,
        );

        // Copy the values to the buffer
        std::ptr::copy_nonoverlapping(
            values.as_ptr().cast::<u8>(),
            self.as_mut_ptr()
                .add(std::mem::size_of::<TraceChunkHeader>())
                .add(num_mem_reads as usize * std::mem::size_of::<MemValue>()),
            std::mem::size_of_val(values),
        );
    }

    pub fn num_mem_reads(&self) -> u64 {
        unsafe {
            std::ptr::read_unaligned(
                self.as_mut_ptr().add(std::mem::offset_of!(TraceChunkHeader, num_mem_reads))
                    as *const u64,
            )
        }
    }

    fn as_mut_ptr(&self) -> *mut u8 {
        self.inner.as_ptr().cast_mut()
    }
}

impl From<TraceChunkBuffer> for Mmap {
    fn from(buffer: TraceChunkBuffer) -> Self {
        buffer.inner.make_read_only().expect("Failed to make trace buf read only")
    }
}
