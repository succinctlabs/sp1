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
use itertools::Itertools;
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

use super::{Fp12, Fp6};

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
    pub x_memory_records: Vec<MemoryWriteRecord>,
    pub y_memory_records: Vec<MemoryReadRecord>,
}

type WordsFieldElement = <U384Field as NumWords>::WordsFieldElement;
const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;
const NUM_FP_MULS: usize = 144;

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Fp6MulCols<T> {
    // c0:
    // self.c0.c0 * b.c0.c0 - self.c0.c1 * b.c0.c1 + self.c1.c0 * b20_m_b21
    //     - self.c1.c1 * b20_p_b21
    //     + self.c2.c0 * b10_m_b11
    //     - self.c2.c1 * b10_p_b11,
    pub c0_b10_p_b11: FieldOpCols<T, U384Field>, // self.c1.c0 + self.c1.c1
    pub c0_b10_m_b11: FieldOpCols<T, U384Field>, // self.c1.c0 - self.c1.c1
    pub c0_b20_p_b21: FieldOpCols<T, U384Field>, // self.c2.c0 + self.c2.c1
    pub c0_b20_m_b21: FieldOpCols<T, U384Field>, // self.c2.c0 - self.c2.c1

    pub c0_a00_t_b00: FieldOpCols<T, U384Field>, // self.c0.c0 * self.b.c0.c0
    pub c0_a01_t_b01: FieldOpCols<T, U384Field>, // self.c0.c1 * self.b.c0.c1
    pub c0_a10_t_b20_m_b21: FieldOpCols<T, U384Field>, // self.c1.c0 * (self.c2.c0 - self.c2.c1)
    pub c0_a11_t_b20_p_b21: FieldOpCols<T, U384Field>, // self.c1.c1 * (self.c2.c0 + self.c2.c1)
    pub c0_a20_t_b10_m_b11: FieldOpCols<T, U384Field>, // self.c2.c0 * (self.c1.c0 - self.c1.c1)
    pub c0_a21_t_b10_p_b11: FieldOpCols<T, U384Field>, // self.c2.c1 * (self.c1.c0 + self.c1.c1)

    pub c0_m_a01_t_b01: FieldOpCols<T, U384Field>, // self.c0.c0 * self.b.c0.c0 - self.c0.c1 * self.b.c0.c1
    pub c0_p_a10_t_b20_m_b21: FieldOpCols<T, U384Field>, // self.c0.c0 * b.c0.c0 - self.c0.c1 * b.c0.c1 + self.c1.c0 * b20_m_b21
    pub c0_m_a11_t_b20_p_b21: FieldOpCols<T, U384Field>, // self.c0.c0 * b.c0.c0 - self.c0.c1 * b.c0.c1 + self.c1.c0 * b20_m_b21 - self.c1.c1 * b20_p_b21
    pub c0_p_a20_t_b10_m_b11: FieldOpCols<T, U384Field>, // self.c0.c0 * b.c0.c0 - self.c0.c1 * b.c0.c1 + self.c1.c0 * b20_m_b21 - self.c1.c1 * b20_p_b21 + self.c2.c0 * b10_m_b11
    pub c0: FieldOpCols<T, U384Field>, // self.c0.c0 * b.c0.c0 - self.c0.c1 * b.c0.c1 + self.c1.c0 * b20_m_b21 - self.c1.c1 * b20_p_b21 + self.c2.c0 * b10_m_b11 - self.c2.c1 * b10_p_b11

    // c1: self.c0.c0 * b.c0.c1
    // + self.c0.c1 * b.c0.c0
    // + self.c1.c0 * b20_p_b21
    // + self.c1.c1 * b20_m_b21
    // + self.c2.c0 * b10_p_b11
    // + self.c2.c1 * b10_m_b11,
    pub c1_a00_t_b01: FieldOpCols<T, U384Field>, // self.c0.c0 * self.b.c0.c1
    pub c1_a01_t_b00: FieldOpCols<T, U384Field>, // self.c0.c1 * self.b.c0.c0
    pub c1_a10_t_b20_p_b21: FieldOpCols<T, U384Field>, // self.c1.c0 * (self.c2.c0 + self.c2.c1)
    pub c1_a11_t_b20_m_b21: FieldOpCols<T, U384Field>, // self.c1.c1 * (self.c2.c0 - self.c2.c1)
    pub c1_a20_t_b10_p_b11: FieldOpCols<T, U384Field>, // self.c2.c0 * (self.c1.c0 + self.c1.c1)
    pub c1_a21_t_b10_m_b11: FieldOpCols<T, U384Field>, // self.c2.c1 * (self.c1.c0 - self.c1.c1)

    pub c1_p_a01_t_b00: FieldOpCols<T, U384Field>, // self.c0.c0 * self.b.c0.c1 + self.c0.c1 * self.b.c0.c0
    pub c1_p_a10_t_b20_p_b21: FieldOpCols<T, U384Field>, // self.c0.c0 * b.c0.c1 + self.c0.c1 * b.c0.c0 + self.c1.c0 * b20_p_b21
    pub c1_p_a11_t_b20_m_b21: FieldOpCols<T, U384Field>, // self.c0.c0 * b.c0.c1 + self.c0.c1 * b.c0.c0 + self.c1.c0 * b20_p_b21 + self.c1.c1 * b20_m_b21
    pub c1_p_a20_t_b10_p_b11: FieldOpCols<T, U384Field>, // self.c0.c0 * b.c0.c1 + self.c0.c1 * b.c0.c0 + self.c1.c0 * b20_p_b21 + self.c1.c1 * b20_m_b21 + self.c2.c0 * b10_p_b11
    pub c1: FieldOpCols<T, U384Field>, // self.c0.c0 * b.c0.c1 + self.c0.c1 * b.c0.c0 + self.c1.c0 * b20_p_b21 + self.c1.c1 * b20_m_b21 + self.c2.c0 * b10_p_b11 + self.c2.c1 * b10_m_b11
}

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Fp6AddCols<T> {
    pub a00_p_b00: FieldOpCols<T, U384Field>, // self.c0.c0 + self.b.c0.c0
    pub a01_p_b01: FieldOpCols<T, U384Field>, // self.c0.c1 + self.b.c0.c1
    pub a10_p_b10: FieldOpCols<T, U384Field>, // self.c1.c0 + self.b.c1.c0
    pub a11_p_b11: FieldOpCols<T, U384Field>, // self.c1.c1 + self.b.c1.c1
    pub a20_p_b20: FieldOpCols<T, U384Field>, // self.c2.c0 + self.b.c2.c0
    pub a21_p_b21: FieldOpCols<T, U384Field>, // self.c2.c1 + self.b.c2.c1
}

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Fp6MulByNonResidue<T> {
    pub c00: FieldOpCols<T, U384Field>, // self.c2.c0 - self.c2.c1
    pub c01: FieldOpCols<T, U384Field>, // self.c2.c0 + self.c2.c1

    pub c10: FieldOpCols<T, U384Field>, // self.c0.c0
    pub c11: FieldOpCols<T, U384Field>, // self.c0.c1

    pub c20: FieldOpCols<T, U384Field>, // self.c1.c0
    pub c21: FieldOpCols<T, U384Field>, // self.c1.c1
}

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct AuxFp12MulCols<T> {
    pub aa: Fp6MulCols<T>,
    pub bb: Fp6MulCols<T>,
    pub o: Fp6AddCols<T>,
    pub y1: Fp6AddCols<T>,         // self.c1 + self.c0
    pub y2: Fp6MulCols<T>,         // (self.c1 + self.c0) * self.o
    pub y3: Fp6AddCols<T>,         // (self.c1 + self.c0) * o  - aa
    pub y: Fp6AddCols<T>,          // (self.c1 + self.c0) * o  - aa - bb
    pub x1: Fp6MulByNonResidue<T>, // bb * non_residue
    pub x: Fp6AddCols<T>,          // bb * non_residue + aa
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
    pub output: AuxFp12MulCols<T>,
}

#[derive(Default)]
pub struct Fp12MulChip;

impl Fp12MulChip {
    pub const fn new() -> Self {
        Self
    }
}

impl<F: PrimeField32> MachineAir<F> for Fp12MulChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Fp12Mul".to_string()
    }

    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        let rows_and_records = input
            .fp12_mul_events
            .chunks(1)
            .map(|events| {
                let mut records = ExecutionRecord::default();
                let mut new_byte_lookup_events = Vec::new();

                let rows = events
                    .iter()
                    .map(|event| {
                        let mut row: [F; NUM_COLS] = [F::zero(); NUM_COLS];
                        let cols: &mut Fp12MulCols<F> = row.as_mut_slice().borrow_mut();
                        // let x = [0..BigUint::from_bytes_le(bytes_to_words_le::<48>(&event.x[0..48]));
                        let x = (0..12)
                            .map(|i| {
                                BigUint::from_bytes_le(&words_to_bytes_le::<48>(
                                    &event.x[i * 48..(i + 1) * 48],
                                ))
                            })
                            .collect_vec();
                        let y = (0..12)
                            .map(|i| {
                                BigUint::from_bytes_le(&words_to_bytes_le::<48>(
                                    &event.y[i * 48..(i + 1) * 48],
                                ))
                            })
                            .collect_vec();

                        // Assign basic values to the columns.
                        cols.is_real = F::one();
                        cols.shard = F::from_canonical_u32(event.shard);
                        cols.channel = F::from_canonical_u32(event.channel);
                        cols.clk = F::from_canonical_u32(event.clk);
                        cols.x_ptr = F::from_canonical_u32(event.x_ptr);
                        cols.y_ptr = F::from_canonical_u32(event.y_ptr);

                        // Populate memory columns.
                        for i in 0..WORDS_FIELD_ELEMENT {
                            cols.x_memory[i].populate(
                                event.channel,
                                event.x_memory_records[i],
                                &mut new_byte_lookup_events,
                            );
                            cols.y_memory[i].populate(
                                event.channel,
                                event.y_memory_records[i],
                                &mut new_byte_lookup_events,
                            );
                        }

                        // Populate the output columns.

                        row
                    })
                    .collect_vec();
            })
            .collect::<Vec<_>>();
        todo!()
    }

    fn included(&self, shard: &Self::Record) -> bool {
        todo!()
    }
}
