use crate::air::{BaseAirBuilder, MachineAir, Polynomial, SP1AirBuilder, WORD_SIZE};
use crate::bytes::event::ByteRecord;
use crate::memory::{value_as_limbs, MemoryReadCols, MemoryWriteCols};
use crate::operations::field::field_op::{FieldOpCols, FieldOperation};
use crate::operations::field::params::NumWords;
use crate::operations::field::params::{Limbs, NumLimbs};
use crate::operations::IsZeroOperation;
use crate::runtime::{ExecutionRecord, Program, Syscall, SyscallCode};
use crate::runtime::{MemoryReadRecord, MemoryWriteRecord};
use crate::stark::MachineRecord;
use crate::syscall::precompiles::SyscallContext;
use crate::utils::ec::uint::U384Field;
use crate::utils::{
    bytes_to_words_le, limbs_from_access, limbs_from_prev_access, pad_rows, words_to_bytes_le,
    words_to_bytes_le_vec,
};
use generic_array::GenericArray;
use num::Zero;
use num::{BigUint, One};
use p3_air::AirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use serde::{Deserialize, Serialize};
use sp1_derive::AlignedBorrow;
use std::borrow::{Borrow, BorrowMut};
use std::mem::size_of;
use typenum::Unsigned;

use super::Fp12;

/// The number of columns in the FpMulCols.
const NUM_COLS: usize = size_of::<Fp12MulCols<u8>>();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fp12MulEvent {
    pub lookup_id: usize,
    pub shard: u32,
    pub channel: u32,
    pub clk: u32,
    pub x_ptr: u32,
    pub x: Vec<u32>,
    pub y_ptr: u32,
    pub y: Vec<u32>,
    pub modulus: Vec<u32>,
    pub x_memory_records: Vec<MemoryWriteRecord>,
    pub y_memory_records: Vec<MemoryReadRecord>,
    pub modulus_memory_records: Vec<MemoryReadRecord>,
}

type WordsFieldElement = <U384Field as NumWords>::WordsFieldElement;
const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;
const NUM_FP_MULS: usize = 144;

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
struct Fp6Cols<T> {
    // c0:
    // self.c0.c0 * b.c0.c0 - self.c0.c1 * b.c0.c1 + self.c1.c0 * b20_m_b21
    //     - self.c1.c1 * b20_p_b21
    //     + self.c2.c0 * b10_m_b11
    //     - self.c2.c1 * b10_p_b11,
    c0_b10_p_b11: FieldOpCols<T, U384Field>, // self.c1.c0 + self.c1.c1
    c0_b10_m_b11: FieldOpCols<T, U384Field>, // self.c1.c0 - self.c1.c1
    c0_b20_p_b21: FieldOpCols<T, U384Field>, // self.c2.c0 + self.c2.c1
    c0_b20_m_b21: FieldOpCols<T, U384Field>, // self.c2.c0 - self.c2.c1

    c0_a00_t_b00: FieldOpCols<T, U384Field>, // self.c0.c0 * self.b.c0.c0
    c0_a01_t_b01: FieldOpCols<T, U384Field>, // self.c0.c1 * self.b.c0.c1
    c0_a10_t_b20_m_b21: FieldOpCols<T, U384Field>, // self.c1.c0 * (self.c2.c0 - self.c2.c1)
    c0_a11_t_b20_p_b21: FieldOpCols<T, U384Field>, // self.c1.c1 * (self.c2.c0 + self.c2.c1)
    c0_a20_t_b10_m_b11: FieldOpCols<T, U384Field>, // self.c2.c0 * (self.c1.c0 - self.c1.c1)
    c0_a21_t_b10_p_b11: FieldOpCols<T, U384Field>, // self.c2.c1 * (self.c1.c0 + self.c1.c1)

    c0_m_a01_t_b01: FieldOpCols<T, U384Field>, // self.c0.c0 * self.b.c0.c0 - self.c0.c1 * self.b.c0.c1
    c0_p_a10_t_b20_m_b21: FieldOpCols<T, U384Field>, // self.c0.c0 * b.c0.c0 - self.c0.c1 * b.c0.c1 + self.c1.c0 * b20_m_b21
    c0_m_a11_t_b20_p_b21: FieldOpCols<T, U384Field>, // self.c0.c0 * b.c0.c0 - self.c0.c1 * b.c0.c1 + self.c1.c0 * b20_m_b21 - self.c1.c1 * b20_p_b21
    c0_p_a20_t_b10_m_b11: FieldOpCols<T, U384Field>, // self.c0.c0 * b.c0.c0 - self.c0.c1 * b.c0.c1 + self.c1.c0 * b20_m_b21 - self.c1.c1 * b20_p_b21 + self.c2.c0 * b10_m_b11
    c0_m_a21_t_b10_p_b11: FieldOpCols<T, U384Field>, // self.c0.c0 * b.c0.c0 - self.c0.c1 * b.c0.c1 + self.c1.c0 * b20_m_b21 - self.c1.c1 * b20_p_b21 + self.c2.c0 * b10_m_b11 - self.c2.c1 * b10_p_b11

    /*
    c1: self.c0.c0 * b.c0.c1
    + self.c0.c1 * b.c0.c0
    + self.c1.c0 * b20_p_b21
    + self.c1.c1 * b20_m_b21
    + self.c2.c0 * b10_p_b11
    + self.c2.c1 * b10_m_b11,
    */
    c1_a00_t_b01: FieldOpCols<T, U384Field>, // self.c0.c0 * self.b.c0.c1
    c1_a01_t_b00: FieldOpCols<T, U384Field>, // self.c0.c1 * self.b.c0.c0
    c1_a10_t_b20_p_b21: FieldOpCols<T, U384Field>, // self.c1.c0 * (self.c2.c0 + self.c2.c1)
    c1_a11_t_b20_m_b21: FieldOpCols<T, U384Field>, // self.c1.c1 * (self.c2.c0 - self.c2.c1)
    c1_a20_t_b10_p_b11: FieldOpCols<T, U384Field>, // self.c2.c0 * (self.c1.c0 + self.c1.c1)
    c1_a21_t_b10_m_b11: FieldOpCols<T, U384Field>, // self.c2.c1 * (self.c1.c0 - self.c1.c1)

    c1_p_a01_t_b00: FieldOpCols<T, U384Field>, // self.c0.c0 * self.b.c0.c1 + self.c0.c1 * self.b.c0.c0
    c1_p_a10_t_b20_p_b21: FieldOpCols<T, U384Field>, // self.c0.c0 * b.c0.c1 + self.c0.c1 * b.c0.c0 + self.c1.c0 * b20_p_b21
    c1_p_a11_t_b20_m_b21: FieldOpCols<T, U384Field>, // self.c0.c0 * b.c0.c1 + self.c0.c1 * b.c0.c0 + self.c1.c0 * b20_p_b21 + self.c1.c1 * b20_m_b21
    c1_p_a20_t_b10_p_b11: FieldOpCols<T, U384Field>, // self.c0.c0 * b.c0.c1 + self.c0.c1 * b.c0.c0 + self.c1.c0 * b20_p_b21 + self.c1.c1 * b20_m_b21 + self.c2.c0 * b10_p_b11
    c1_p_a21_t_b10_m_b11: FieldOpCols<T, U384Field>, // self.c0.c0 * b.c0.c1 + self.c0.c1 * b.c0.c0 + self.c1.c0 * b20_p_b21 + self.c1.c1 * b20_m_b21 + self.c2.c0 * b10_p_b11 + self.c2.c1 * b10_m_b11
}

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
struct Fp12Cols<T> {
    c0: Fp6Cols<T>,
    c1: Fp6Cols<T>,
    c2: Fp6Cols<T>,
}

/// A set of columns for the FpMul operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Fp12MulCols<T> {
    pub is_real: T,
    pub shard: T,
    pub channel: T,
    pub clk: T,
    pub nonce: T,
    pub x_ptr: T,
    pub y_ptr: T,
    pub x_memory: GenericArray<MemoryWriteCols<T>, WordsFieldElement>,
    pub y_memory: GenericArray<MemoryReadCols<T>, WordsFieldElement>,
    pub col: Fp12Cols<T>,
}

#[derive(Default)]
pub struct Fp12MulChip;

impl Fp12MulChip {
    pub const fn new() -> Self {
        Self
    }
}

// impl<F: PrimeField32> MachineAir<F> for Fp12MulChip {
//     type Record = ExecutionRecord;

//     type Program = Program;

//     fn name(&self) -> String {
//         "Fp12Mul".toString()
//     }

//     fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
//         todo!()
//     }

//     fn included(&self, shard: &Self::Record) -> bool {
//         todo!()
//     }
// }
