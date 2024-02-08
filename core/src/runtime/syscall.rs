use crate::runtime::{Register, Runtime};
use crate::{cpu::MemoryReadRecord, cpu::MemoryWriteRecord, runtime::Segment};

/// A system call is invoked by the the `ecall` instruction with a specific value in register t0.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum SyscallCode {
    /// Halts the program.
    HALT = 100,

    /// Loads a word supplied from the prover.
    LWA = 101,

    /// Executes the `SHA_EXTEND` precompile.
    SHA_EXTEND = 102,

    /// Executes the `SHA_COMPRESS` precompile.
    SHA_COMPRESS = 103,

    /// Executes the `ED_ADD` precompile.
    ED_ADD = 104,

    /// Executes the `ED_DECOMPRESS` precompile.
    ED_DECOMPRESS = 105,

    /// Executes the `KECCAK_PERMUTE` precompile.
    KECCAK_PERMUTE = 106,

    /// Executes the `SECP256K1_ADD` precompile.
    SECP256K1_ADD = 107,

    /// Executes the `SECP256K1_DOUBLE` precompile.
    SECP256K1_DOUBLE = 108,

    /// Executes the `K256_DECOMPRESS` precompile.
    SECP256K1_DECOMPRESS = 109,

    /// Enter unconstrained block.
    ENTER_UNCONSTRAINED = 110,

    /// Exit unconstrained block.
    EXIT_UNCONSTRAINED = 111,

    WRITE = 999,
}

impl SyscallCode {
    /// Create a syscall from a u32.
    pub fn from_u32(value: u32) -> Self {
        match value {
            100 => SyscallCode::HALT,
            101 => SyscallCode::LWA,
            102 => SyscallCode::SHA_EXTEND,
            103 => SyscallCode::SHA_COMPRESS,
            104 => SyscallCode::ED_ADD,
            105 => SyscallCode::ED_DECOMPRESS,
            106 => SyscallCode::KECCAK_PERMUTE,
            107 => SyscallCode::SECP256K1_ADD,
            108 => SyscallCode::SECP256K1_DOUBLE,
            109 => SyscallCode::SECP256K1_DECOMPRESS,
            110 => SyscallCode::ENTER_UNCONSTRAINED,
            111 => SyscallCode::EXIT_UNCONSTRAINED,
            999 => SyscallCode::WRITE,
            _ => panic!("invalid syscall number: {}", value),
        }
    }
}

pub trait Syscall {
    /// Execute the syscall and return the resulting value of register a0.
    fn execute(&self, rt: &mut SyscallRuntime) -> u32;

    /// The number of extra cycles that the syscall takes to execute. Unless this syscall is complex
    /// and requires many cycles, this should be zero.
    fn num_extra_cycles(&self) -> u32;
}

/// A runtime for precompiles that is protected so that developers cannot arbitrarily modify the runtime.
pub struct SyscallRuntime<'a> {
    current_segment: u32,
    pub clk: u32,

    rt: &'a mut Runtime, // Reference
}

impl<'a> SyscallRuntime<'a> {
    pub fn new(runtime: &'a mut Runtime) -> Self {
        let current_segment = runtime.current_segment();
        let clk = runtime.state.clk;
        Self {
            current_segment,
            clk,
            rt: runtime,
        }
    }

    pub fn segment_mut(&mut self) -> &mut Segment {
        &mut self.rt.record
    }

    pub fn segment_clk(&self) -> u32 {
        self.rt.state.segment_clk
    }

    pub fn mr(&mut self, addr: u32) -> (MemoryReadRecord, u32) {
        let record = self.rt.mr_core(addr, self.current_segment, self.clk);
        (record, record.value)
    }

    pub fn mr_slice(&mut self, addr: u32, len: usize) -> (Vec<MemoryReadRecord>, Vec<u32>) {
        let mut records = Vec::new();
        let mut values = Vec::new();
        for i in 0..len {
            let (record, value) = self.mr(addr + i as u32 * 4);
            records.push(record);
            values.push(value);
        }
        (records, values)
    }

    pub fn mw(&mut self, addr: u32, value: u32) -> MemoryWriteRecord {
        self.rt.mw_core(addr, value, self.current_segment, self.clk)
    }

    pub fn mw_slice(&mut self, addr: u32, values: &[u32]) -> Vec<MemoryWriteRecord> {
        let mut records = Vec::new();
        for i in 0..values.len() {
            let record = self.mw(addr + i as u32 * 4, values[i]);
            records.push(record);
        }
        records
    }

    /// Get the current value of a register, but doesn't use a memory record.
    /// This is generally unconstrained, so you must be careful using it.
    pub fn register_unsafe(&self, register: Register) -> u32 {
        self.rt.register(register)
    }

    pub fn byte_unsafe(&self, addr: u32) -> u8 {
        self.rt.byte(addr)
    }

    pub fn word_unsafe(&self, addr: u32) -> u32 {
        self.rt.word(addr)
    }

    pub fn slice_unsafe(&self, addr: u32, len: usize) -> Vec<u32> {
        let mut values = Vec::new();
        for i in 0..len {
            values.push(self.rt.word(addr + i as u32 * 4));
        }
        values
    }
}
