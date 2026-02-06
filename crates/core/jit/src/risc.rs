use std::{marker::PhantomData, sync::Arc};

use memmap2::Mmap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RiscRegister {
    X0 = 0,
    X1 = 1,
    X2 = 2,
    X3 = 3,
    X4 = 4,
    X5 = 5,
    X6 = 6,
    X7 = 7,
    X8 = 8,
    X9 = 9,
    X10 = 10,
    X11 = 11,
    X12 = 12,
    X13 = 13,
    X14 = 14,
    X15 = 15,
    X16 = 16,
    X17 = 17,
    X18 = 18,
    X19 = 19,
    X20 = 20,
    X21 = 21,
    X22 = 22,
    X23 = 23,
    X24 = 24,
    X25 = 25,
    X26 = 26,
    X27 = 27,
    X28 = 28,
    X29 = 29,
    X30 = 30,
    X31 = 31,
}

impl RiscRegister {
    pub fn all_registers() -> &'static [RiscRegister] {
        &[
            RiscRegister::X0,
            RiscRegister::X1,
            RiscRegister::X2,
            RiscRegister::X3,
            RiscRegister::X4,
            RiscRegister::X5,
            RiscRegister::X6,
            RiscRegister::X7,
            RiscRegister::X8,
            RiscRegister::X9,
            RiscRegister::X10,
            RiscRegister::X11,
            RiscRegister::X12,
            RiscRegister::X13,
            RiscRegister::X14,
            RiscRegister::X15,
            RiscRegister::X16,
            RiscRegister::X17,
            RiscRegister::X18,
            RiscRegister::X19,
            RiscRegister::X20,
            RiscRegister::X21,
            RiscRegister::X22,
            RiscRegister::X23,
            RiscRegister::X24,
            RiscRegister::X25,
            RiscRegister::X26,
            RiscRegister::X27,
            RiscRegister::X28,
            RiscRegister::X29,
            RiscRegister::X30,
            RiscRegister::X31,
        ]
    }
}

/// ALU operations can either have register or immediate operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiscOperand {
    Register(RiscRegister),
    Immediate(i32),
}

impl From<RiscRegister> for RiscOperand {
    fn from(reg: RiscRegister) -> Self {
        RiscOperand::Register(reg)
    }
}

impl From<u32> for RiscOperand {
    fn from(imm: u32) -> Self {
        RiscOperand::Immediate(imm as i32)
    }
}

impl From<i32> for RiscOperand {
    fn from(imm: i32) -> Self {
        RiscOperand::Immediate(imm)
    }
}

impl From<u64> for RiscOperand {
    fn from(imm: u64) -> Self {
        RiscOperand::Immediate(imm as i32)
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemValue {
    pub clk: u64,
    pub value: u64,
}

/// A convience structure for getting offsets of fields in the actual [TraceChunk].
#[repr(C)]
pub struct TraceChunkHeader {
    pub start_registers: [u64; 32],
    pub pc_start: u64,
    pub clk_start: u64,
    pub clk_end: u64,
    pub num_mem_reads: u64,
}

#[repr(C)]
#[derive(Clone)]
pub struct TraceChunkRaw(Arc<Mmap>);

impl TraceChunkRaw {
    /// # Safety
    ///
    /// - The mmap must be a valid [`TraceChunkHeader`].
    /// - The mmap must contain valid [`MemValue`]s in after the header.
    /// - The `num_mem_reads` must be the number of [`MemValue`]s in the mmap after the header.
    pub unsafe fn new(inner: Mmap) -> Self {
        Self(Arc::new(inner))
    }
}

impl MinimalTrace for TraceChunkRaw {
    fn start_registers(&self) -> [u64; 32] {
        let offset = std::mem::offset_of!(TraceChunkHeader, start_registers);

        unsafe { std::ptr::read_unaligned(self.0.as_ptr().add(offset) as *const [u64; 32]) }
    }

    fn pc_start(&self) -> u64 {
        let offset = std::mem::offset_of!(TraceChunkHeader, pc_start);

        unsafe { std::ptr::read_unaligned(self.0.as_ptr().add(offset) as *const u64) }
    }

    fn clk_start(&self) -> u64 {
        let offset = std::mem::offset_of!(TraceChunkHeader, clk_start);

        unsafe { std::ptr::read_unaligned(self.0.as_ptr().add(offset) as *const u64) }
    }

    fn clk_end(&self) -> u64 {
        let offset = std::mem::offset_of!(TraceChunkHeader, clk_end);

        unsafe { std::ptr::read_unaligned(self.0.as_ptr().add(offset) as *const u64) }
    }

    fn num_mem_reads(&self) -> u64 {
        let offset = std::mem::offset_of!(TraceChunkHeader, num_mem_reads);

        unsafe { std::ptr::read_unaligned(self.0.as_ptr().add(offset) as *const u64) }
    }

    fn mem_reads(&self) -> MemReads<'_> {
        let header_end = std::mem::size_of::<TraceChunkHeader>();
        let len = self.num_mem_reads() as usize;

        debug_assert!(self.0.len() - header_end >= len);

        // SAFETY:
        // - The memory is valid assuming num_mem_reads is correct.
        // - The memory is technically always valid for reads since all bitpatterns are valid for
        //   `MemValue`.
        unsafe { MemReads::new(self.0.as_ptr().add(header_end) as *const MemValue, len) }
    }
}

pub struct MemReads<'a> {
    inner: *const MemValue,
    end: *const MemValue,
    /// Capture the lifetime of the buffer for saftey reasons.
    _phantom: PhantomData<&'a ()>,
}

impl<'a> MemReads<'a> {
    /// # Safety
    ///
    /// - The underlying memory is valid and contains valid `MemValue`s.
    /// - The length is the number of `MemValue`s in the underlying memory.
    pub(crate) unsafe fn new(inner: *const MemValue, len: usize) -> Self {
        debug_assert!(inner.is_aligned(), "MemReads ptr is not aligned");

        Self { inner, end: inner.add(len), _phantom: PhantomData }
    }

    /// Advance the pointer by `n` elements.
    ///
    /// # Panics
    ///
    /// Panics if `n` is greater than the purported length of the underlying buffer.
    pub fn advance(&mut self, n: usize) {
        unsafe {
            let advanced = self.inner.add(n);

            if advanced > self.end {
                panic!("Cannot advance by more than the length of the slice");
            }

            self.inner = advanced;
        }
    }

    /// Get the raw pointer to the head of the slice.
    pub fn head_raw(&self) -> *const MemValue {
        self.inner
    }

    /// The remaining length of the slice from our current position.
    #[must_use]
    pub fn len(&self) -> usize {
        unsafe { self.end.offset_from_unsigned(self.inner) }
    }

    /// Check if the iterator is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner == self.end
    }
}

impl<'a> Iterator for MemReads<'a> {
    type Item = MemValue;

    fn next(&mut self) -> Option<Self::Item> {
        if self.inner == self.end {
            None
        } else {
            let value = unsafe { std::ptr::read(self.inner) };
            self.inner = unsafe { self.inner.add(1) };

            Some(value)
        }
    }
}

/// A trace chunk is all the data needed to continue the execution of a program at
/// pc_start/clk_start.
///
/// We transmute this type directly from bytes, and the buffer should be of [TraceChunkRaw] form,
/// plus, a slice of the memory reads.
///
/// When we read this type from the buffer, we will copy the registers, the pc/clk start and end,
/// and take a pointer to the memory reads, by reading the num_mem_vals field.
///
/// The fields should be placed in the buffer according to the layout of [TraceChunkRaw].
#[repr(C)]
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceChunk {
    pub start_registers: [u64; 32],
    pub pc_start: u64,
    pub clk_start: u64,
    pub clk_end: u64,
    #[serde(serialize_with = "ser::serialize_mem_reads")]
    #[serde(deserialize_with = "ser::deserialize_mem_reads")]
    pub mem_reads: Arc<[MemValue]>,
}

impl From<TraceChunkRaw> for TraceChunk {
    fn from(raw: TraceChunkRaw) -> Self {
        TraceChunk::copy_from_bytes(raw.0.as_ref())
    }
}

impl TraceChunk {
    /// Copy the bytes into a [TraceChunk]. We dont just back it with the original bytes,
    /// since this type is likely to be sent off to worker for proving.
    ///
    /// # Note:
    /// This method will panic if the buffer is not large enough,
    /// or the number of reads causes an overflow.
    pub fn copy_from_bytes(src: &[u8]) -> Self {
        const HDR: usize = size_of::<TraceChunkHeader>();

        /* ---------- 1. header must fit ---------- */
        if src.len() < HDR {
            panic!("TraceChunk header too small");
        }

        /* ---------- 2. copy-out the header ---------- */
        // SAFETY:
        // we just checked that `src` contains at least `HDR` bytes,
        // and `read_unaligne
        //
        // Note: All bit patterns are valid for `TraceChunkRaw`.
        let raw: TraceChunkHeader =
            unsafe { core::ptr::read_unaligned(src.as_ptr() as *const TraceChunkHeader) };

        /* ---------- 3. tail must fit ---------- */
        let n_words = raw.num_mem_reads as usize;
        let n_bytes = n_words.checked_mul(size_of::<MemValue>()).expect("Num mem reads too large");
        let total = HDR.checked_add(n_bytes).expect("Num mem reads too large");
        if src.len() < total {
            panic!("TraceChunk tail too small");
        }

        /* ---------- 4. extract tail ---------- */
        let tail = &src[HDR..total]; // only after the length check

        let mem_reads = Arc::new_uninit_slice(n_words);

        // SAFETY:
        // - The tail contains valid u64s, so doing a bitwise copy preserves the validity and
        //   endianness.
        // - tail is likely unaligned, so casting to a u8 pointer gives the alignmnt guarantee the
        //   compiler needs to do a copy.
        // - `mem_reads` was just allocated to have enough space.
        // - u8 has minimum alignment, so casting the pointer allocated by the vec is valid.
        // - The cast from const -> mut is valid since there are no other references to the memory.
        //
        // This trick is mostly taken from [`std::ptr::read_unaligned`]
        // see: <https://doc.rust-lang.org/src/core/ptr/mod.rs.html#1811>.
        unsafe {
            std::ptr::copy_nonoverlapping(tail.as_ptr(), mem_reads.as_ptr() as *mut u8, n_bytes)
        };

        Self {
            start_registers: raw.start_registers,
            pc_start: raw.pc_start,
            clk_start: raw.clk_start,
            clk_end: raw.clk_end,
            // SAFETY: We know the memory is initialized, so we can assume it.
            mem_reads: unsafe { mem_reads.assume_init() },
        }
    }
}

/// A trait that represents a minimal trace.
///
/// A minimal trace is the minimum required information to rexecute from
/// `pc_start` and `clk_start` -> `clk_end`.
///
/// It effectively acts as an oracle for the results of memory read operations.
pub trait MinimalTrace: Clone + Send + Sync + 'static {
    fn start_registers(&self) -> [u64; 32];

    fn pc_start(&self) -> u64;

    fn clk_start(&self) -> u64;

    fn clk_end(&self) -> u64;

    fn num_mem_reads(&self) -> u64;

    fn mem_reads(&self) -> MemReads<'_>;
}

impl MinimalTrace for TraceChunk {
    fn start_registers(&self) -> [u64; 32] {
        self.start_registers
    }

    fn pc_start(&self) -> u64 {
        self.pc_start
    }

    fn clk_start(&self) -> u64 {
        self.clk_start
    }

    fn clk_end(&self) -> u64 {
        self.clk_end
    }

    fn num_mem_reads(&self) -> u64 {
        self.mem_reads.len() as u64
    }

    fn mem_reads(&self) -> MemReads<'_> {
        // SAFETY:
        // - The memory is technically always valid for reads since all bitpatterns are valid for
        //   `MemValue`.
        // - the length comes directly from the Vec, which we know to be valid.
        unsafe { MemReads::new(self.mem_reads.as_ptr(), self.mem_reads.len()) }
    }
}

mod ser {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize_mem_reads<S: Serializer>(
        mem_reads: &Arc<[MemValue]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let as_vec: Vec<MemValue> = Vec::from(&mem_reads[..]);

        Vec::serialize(&as_vec, serializer)
    }

    pub fn deserialize_mem_reads<'a, D: Deserializer<'a>>(
        deserializer: D,
    ) -> Result<Arc<[MemValue]>, D::Error> {
        let as_vec = Vec::deserialize(deserializer)?;

        Ok(as_vec.into())
    }

    #[test]
    #[cfg(test)]
    fn test_mem_reads() {
        let mem_reads = Arc::new([MemValue { clk: 0, value: 0 }, MemValue { clk: 1, value: 1 }]);
        let trace = TraceChunk {
            start_registers: [5; 32],
            pc_start: 6,
            clk_start: 7,
            clk_end: 8,
            mem_reads,
        };

        let serialized = bincode::serialize(&trace).unwrap();
        let deserialized = bincode::deserialize(&serialized).unwrap();

        assert_eq!(trace, deserialized);
    }
}
