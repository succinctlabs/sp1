pub mod edwards;
pub mod k256;
pub mod keccak256;
pub mod sha256;
pub mod weierstrass;

use num::BigUint;

use crate::air::CurtaAirBuilder;
use crate::operations::field::params::Limbs;
use crate::runtime::{Register, Runtime};
use crate::utils::ec::field::FieldParameters;
use crate::utils::ec::{AffinePoint, EllipticCurve};
use crate::{cpu::MemoryReadRecord, cpu::MemoryWriteRecord, runtime::Segment};

/// A runtime for precompiles that is protected so that developers cannot arbitrarily modify the runtime.
pub struct PrecompileRuntime<'a> {
    current_segment: u32,
    pub clk: u32,

    rt: &'a mut Runtime, // Reference
}

impl<'a> PrecompileRuntime<'a> {
    pub fn new(runtime: &'a mut Runtime) -> Self {
        let current_segment = runtime.current_segment();
        let clk = runtime.clk;
        Self {
            current_segment,
            clk,
            rt: runtime,
        }
    }

    pub fn segment_mut(&mut self) -> &mut Segment {
        &mut self.rt.segment
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

/// Elliptic curve add event.
#[derive(Debug, Clone, Copy)]
pub struct ECAddEvent {
    pub clk: u32,
    pub p_ptr: u32,
    pub p: [u32; 16],
    pub q_ptr: u32,
    pub q: [u32; 16],
    pub q_ptr_record: MemoryReadRecord,
    pub p_memory_records: [MemoryWriteRecord; 16],
    pub q_memory_records: [MemoryReadRecord; 16],
}

pub fn create_ec_add_event<E: EllipticCurve>(rt: &mut PrecompileRuntime) -> ECAddEvent {
    let a0 = crate::runtime::Register::X10;
    let a1 = crate::runtime::Register::X11;

    let start_clk = rt.clk;

    // TODO: these will have to be be constrained, but can do it later.
    let p_ptr = rt.register_unsafe(a0);
    if p_ptr % 4 != 0 {
        panic!();
    }

    let (q_ptr_record, q_ptr) = rt.mr(a1 as u32);
    if q_ptr % 4 != 0 {
        panic!();
    }

    let p: [u32; 16] = rt.slice_unsafe(p_ptr, 16).try_into().unwrap();
    let (q_memory_records_vec, q_vec) = rt.mr_slice(q_ptr, 16);
    let q_memory_records = q_memory_records_vec.try_into().unwrap();
    let q: [u32; 16] = q_vec.try_into().unwrap();
    // When we write to p, we want the clk to be incremented.
    rt.clk += 4;

    let p_affine = AffinePoint::<E>::from_words_le(&p);
    let q_affine = AffinePoint::<E>::from_words_le(&q);
    let result_affine = p_affine + q_affine;
    let result_words = result_affine.to_words_le();

    let p_memory_records = rt.mw_slice(p_ptr, &result_words).try_into().unwrap();

    rt.clk += 4;

    ECAddEvent {
        clk: start_clk,
        p_ptr,
        p,
        q_ptr,
        q,
        q_ptr_record,
        p_memory_records,
        q_memory_records,
    }
}

/// Elliptic curve double event.
#[derive(Debug, Clone, Copy)]
pub struct ECDoubleEvent {
    pub clk: u32,
    pub p_ptr: u32,
    pub p: [u32; 16],
    pub p_memory_records: [MemoryWriteRecord; 16],
}

pub fn create_ec_double_event<E: EllipticCurve>(rt: &mut PrecompileRuntime) -> ECDoubleEvent {
    let a0 = crate::runtime::Register::X10;

    let start_clk = rt.clk;

    // TODO: these will have to be be constrained, but can do it later.
    let p_ptr = rt.register_unsafe(a0);
    if p_ptr % 4 != 0 {
        panic!();
    }

    let p: [u32; 16] = rt.slice_unsafe(p_ptr, 16).try_into().unwrap();

    // When we write to p, we want the clk to be incremented.
    rt.clk += 4;

    let p_affine = AffinePoint::<E>::from_words_le(&p);
    let result_affine = E::ec_double(&p_affine);
    let result_words = result_affine.to_words_le();

    let p_memory_records = rt.mw_slice(p_ptr, &result_words).try_into().unwrap();

    rt.clk += 4;

    ECDoubleEvent {
        clk: start_clk,
        p_ptr,
        p,
        p_memory_records,
    }
}

pub fn limbs_from_biguint<AB, F: FieldParameters>(value: &BigUint) -> Limbs<AB::Expr>
where
    AB: CurtaAirBuilder,
{
    let a_const = F::to_limbs_field::<AB::F>(value);
    Limbs::<AB::Expr>(a_const.0.map(|x| x.into()))
}
