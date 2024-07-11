use crate::air::{BaseAirBuilder, MachineAir, Polynomial, SP1AirBuilder, WORD_SIZE};
use crate::bytes::event::ByteRecord;
use crate::memory::{value_as_limbs, MemoryReadCols, MemoryWriteCols};
use crate::operations::field::field_op::{FieldOpCols, FieldOperation};
use crate::operations::field::params::{FieldParameters, NumWords};
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
use amcl::bls381::fp12;
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
use std::marker::PhantomData;
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
    // a.c0.c0 * b.c0.c0 - a.c0.c1 * b.c0.c1 + a.c1.c0 * b20_m_b21
    //     - a.c1.c1 * b20_p_b21
    //     + a.c2.c0 * b10_m_b11
    //     - a.c2.c1 * b10_p_b11,
    pub c0_b10_p_b11: FieldOpCols<T, U384Field>, // a.c1.c0 + b.c1.c1
    pub c0_b10_m_b11: FieldOpCols<T, U384Field>, // a.c1.c0 - b.c1.c1
    pub c0_b20_p_b21: FieldOpCols<T, U384Field>, // a.c2.c0 + b.c2.c1
    pub c0_b20_m_b21: FieldOpCols<T, U384Field>, // a.c2.c0 - b.c2.c1

    pub c0_a00_t_b00: FieldOpCols<T, U384Field>, // a.c0.c0 * b.c0.c0
    pub c0_a01_t_b01: FieldOpCols<T, U384Field>, // a.c0.c1 * b.c0.c1
    pub c0_a10_t_b20_m_b21: FieldOpCols<T, U384Field>, // a.c1.c0 * (a.c2.c0 - b.c2.c1)
    pub c0_a11_t_b20_p_b21: FieldOpCols<T, U384Field>, // a.c1.c1 * (a.c2.c0 + b.c2.c1)
    pub c0_a20_t_b10_m_b11: FieldOpCols<T, U384Field>, // a.c2.c0 * (a.c1.c0 - b.c1.c1)
    pub c0_a21_t_b10_p_b11: FieldOpCols<T, U384Field>, // a.c2.c1 * (a.c1.c0 + b.c1.c1)

    pub c0_m_a01_t_b01: FieldOpCols<T, U384Field>, // a.c0.c0 * b.c0.c0 - a.c0.c1 * b.c0.c1
    pub c0_p_a10_t_b20_m_b21: FieldOpCols<T, U384Field>, // a.c0.c0 * b.c0.c0 - a.c0.c1 * b.c0.c1 + a.c1.c0 * b20_m_b21
    pub c0_m_a11_t_b20_p_b21: FieldOpCols<T, U384Field>, // a.c0.c0 * b.c0.c0 - a.c0.c1 * b.c0.c1 + a.c1.c0 * b20_m_b21 - a.c1.c1 * b20_p_b21
    pub c0_p_a20_t_b10_m_b11: FieldOpCols<T, U384Field>, // a.c0.c0 * b.c0.c0 - a.c0.c1 * b.c0.c1 + a.c1.c0 * b20_m_b21 - a.c1.c1 * b20_p_b21 + a.c2.c0 * b10_m_b11
    pub c0: FieldOpCols<T, U384Field>, // a.c0.c0 * b.c0.c0 - a.c0.c1 * b.c0.c1 + a.c1.c0 * b20_m_b21 - a.c1.c1 * b20_p_b21 + a.c2.c0 * b10_m_b11 - a.c2.c1 * b10_p_b11

    // c1: a.c0.c0 * b.c0.c1
    // + a.c0.c1 * b.c0.c0
    // + a.c1.c0 * b20_p_b21
    // + a.c1.c1 * b20_m_b21
    // + a.c2.c0 * b10_p_b11
    // + a.c2.c1 * b10_m_b11,
    pub c1_a00_t_b01: FieldOpCols<T, U384Field>, // a.c0.c0 * b.c0.c1
    pub c1_a01_t_b00: FieldOpCols<T, U384Field>, // a.c0.c1 * b.c0.c0
    pub c1_a10_t_b20_p_b21: FieldOpCols<T, U384Field>, // a.c1.c0 * (a.c2.c0 + a.c2.c1)
    pub c1_a11_t_b20_m_b21: FieldOpCols<T, U384Field>, // a.c1.c1 * (a.c2.c0 - a.c2.c1)
    pub c1_a20_t_b10_p_b11: FieldOpCols<T, U384Field>, // a.c2.c0 * (a.c1.c0 + a.c1.c1)
    pub c1_a21_t_b10_m_b11: FieldOpCols<T, U384Field>, // a.c2.c1 * (a.c1.c0 - a.c1.c1)

    pub c1_p_a01_t_b00: FieldOpCols<T, U384Field>, // a.c0.c0 * b.c0.c1 + a.c0.c1 * b.c0.c0
    pub c1_p_a10_t_b20_p_b21: FieldOpCols<T, U384Field>, // a.c0.c0 * b.c0.c1 + a.c0.c1 * b.c0.c0 + a.c1.c0 * b20_p_b21
    pub c1_p_a11_t_b20_m_b21: FieldOpCols<T, U384Field>, // a.c0.c0 * b.c0.c1 + a.c0.c1 * b.c0.c0 + a.c1.c0 * b20_p_b21 + a.c1.c1 * b20_m_b21
    pub c1_p_a20_t_b10_p_b11: FieldOpCols<T, U384Field>, // a.c0.c0 * b.c0.c1 + a.c0.c1 * b.c0.c0 + a.c1.c0 * b20_p_b21 + a.c1.c1 * b20_m_b21 + a.c2.c0 * b10_p_b11
    pub c1: FieldOpCols<T, U384Field>, // a.c0.c0 * b.c0.c1 + a.c0.c1 * b.c0.c0 + a.c1.c0 * b20_p_b21 + a.c1.c1 * b20_m_b21 + a.c2.c0 * b10_p_b11 + a.c2.c1 * b10_m_b11
}

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Fp6AddCols<T> {
    pub a00_p_b00: FieldOpCols<T, U384Field>, // a.c0.c0 + b.c0.c0
    pub a01_p_b01: FieldOpCols<T, U384Field>, // a.c0.c1 + b.c0.c1
    pub a10_p_b10: FieldOpCols<T, U384Field>, // a.c1.c0 + b.c1.c0
    pub a11_p_b11: FieldOpCols<T, U384Field>, // a.c1.c1 + b.c1.c1
    pub a20_p_b20: FieldOpCols<T, U384Field>, // a.c2.c0 + b.c2.c0
    pub a21_p_b21: FieldOpCols<T, U384Field>, // a.c2.c1 + b.c2.c1
}

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Fp6MulByNonResidue<T> {
    pub c00: FieldOpCols<T, U384Field>, // a.c2.c0 - a.c2.c1
    pub c01: FieldOpCols<T, U384Field>, // a.c2.c0 + a.c2.c1

    pub c10: FieldOpCols<T, U384Field>, // a.c0.c0
    pub c11: FieldOpCols<T, U384Field>, // a.c0.c1

    pub c20: FieldOpCols<T, U384Field>, // a.c1.c0
    pub c21: FieldOpCols<T, U384Field>, // a.c1.c1
}

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct AuxFp12MulCols<T> {
    pub aa: Fp6MulCols<T>,
    pub bb: Fp6MulCols<T>,
    pub o: Fp6AddCols<T>,
    pub y1: Fp6AddCols<T>,         // a.c1 + a.c0
    pub y2: Fp6MulCols<T>,         // (a.c1 + a.c0) * a.o
    pub y3: Fp6AddCols<T>,         // (a.c1 + a.c0) * o  - aa
    pub y: Fp6AddCols<T>,          // (a.c1 + a.c0) * o  - aa - bb
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
pub struct Fp12MulChip<E> {
    _marker: PhantomData<E>,
}

impl<E: FieldParameters> Fp12MulChip<E> {
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField32, E: FieldParameters> MachineAir<F> for Fp12MulChip {
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
                        let modulus = BigUint::from_bytes_le(E::MODULUS);

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

                        // // Populate the output columns.
                        // let a000 = &x[0];
                        // let a001 = &x[1];
                        // let a010 = &x[2];
                        // let a011 = &x[3];
                        // let a020 = &x[4];
                        // let a021 = &x[5];
                        // let a100 = &x[6];
                        // let a101 = &x[7];
                        // let a110 = &x[8];
                        // let a111 = &x[9];
                        // let a120 = &x[10];
                        // let a121 = &x[11];

                        // let b000 = &y[0];
                        // let b001 = &y[1];
                        // let b010 = &y[2];
                        // let b011 = &y[3];
                        // let b020 = &y[4];
                        // let b021 = &y[5];
                        // let b100 = &y[6];
                        // let b101 = &y[7];
                        // let b110 = &y[8];
                        // let b111 = &y[9];
                        // let b120 = &y[10];
                        // let b121 = &y[11];

                        let mul = |dest: FieldOpCols<F, U384Field>,
                                   a: &BigUint,
                                   b: &BigUint|
                         -> BigUint {
                            dest.populate_with_modulus(
                                &mut new_byte_lookup_events,
                                event.shard,
                                event.channel,
                                a,
                                b,
                                &modulus,
                                FieldOperation::Mul,
                            );
                            (a * b) % &modulus
                        };

                        let add = |dest: FieldOpCols<F, U384Field>,
                                   a: &BigUint,
                                   b: &BigUint|
                         -> BigUint {
                            dest.populate_with_modulus(
                                &mut new_byte_lookup_events,
                                event.shard,
                                event.channel,
                                a,
                                b,
                                &modulus,
                                FieldOperation::Add,
                            );
                            (a * b) % &modulus
                        };

                        let sub = |dest: FieldOpCols<F, U384Field>,
                                   a: &BigUint,
                                   b: &BigUint|
                         -> BigUint {
                            dest.populate_with_modulus(
                                &mut new_byte_lookup_events,
                                event.shard,
                                event.channel,
                                a,
                                b,
                                &modulus,
                                FieldOperation::Sub,
                            );
                            (a * b) % &modulus
                        };

                        let sum_of_products = |dest: Fp6MulCols<F>,
                                               a: [&BigUint; 6],
                                               b: [&BigUint; 6]|
                         -> (&BigUint, &BigUint) {
                            let a00 = a[0];
                            let a01 = a[1];
                            let a10 = a[2];
                            let a11 = a[3];
                            let a20 = a[4];
                            let a21 = a[5];

                            let b00 = b[0];
                            let b01 = b[1];
                            let b10 = b[2];
                            let b11 = b[3];
                            let b20 = b[4];
                            let b21 = b[5];

                            // c0
                            let c0_b10_p_b11 = &add(dest.c0_b10_p_b11, a10, b11);
                            let c0_b10_m_b11 = &sub(dest.c0_b10_m_b11, a10, b11);
                            let c0_b20_p_b21 = &add(dest.c0_b20_p_b21, a20, b21);
                            let c0_b20_m_b21 = &sub(dest.c0_b20_m_b21, a20, b21);

                            let c0_a00_t_b00 = &mul(dest.c0_a00_t_b00, a00, b00);
                            let c0_a01_t_b01 = &mul(dest.c0_a01_t_b01, a01, b01);
                            let c0_a10_t_b20_m_b21 = &mul(dest.c0_a10_t_b20_m_b21, a10, b20);
                            let c0_a11_t_b20_p_b21 = &mul(dest.c0_a11_t_b20_p_b21, a11, b21);
                            let c0_a20_t_b10_m_b11 = &mul(dest.c0_a20_t_b10_m_b11, a20, b10);
                            let c0_a21_t_b10_p_b11 = &mul(dest.c0_a21_t_b10_p_b11, a21, b11);

                            let c0_m_a01_t_b01 =
                                &sub(dest.c0_m_a01_t_b01, c0_a00_t_b00, c0_a01_t_b01);
                            let c0_p_a10_t_b20_m_b21 =
                                &add(dest.c0_p_a10_t_b20_m_b21, c0_m_a01_t_b01, c0_a01_t_b01);
                            let c0_m_a11_t_b20_p_b21 = &sub(
                                dest.c0_m_a11_t_b20_p_b21,
                                c0_p_a10_t_b20_m_b21,
                                c0_a01_t_b01,
                            );
                            let c0_p_a20_t_b10_m_b11 = &add(
                                dest.c0_p_a20_t_b10_m_b11,
                                c0_m_a11_t_b20_p_b21,
                                c0_a01_t_b01,
                            );
                            let c0 = &sub(dest.c0, c0_p_a20_t_b10_m_b11, c0_a21_t_b10_p_b11);

                            // c1
                            let c1_a00_t_b01 = &mul(dest.c1_a00_t_b01, a00, b01);
                            let c1_a01_t_b00 = &mul(dest.c1_a01_t_b00, a01, b00);
                            let c1_a10_t_b20_p_b21 =
                                &mul(dest.c1_a10_t_b20_p_b21, a10, c0_b20_p_b21);
                            let c1_a11_t_b20_m_b21 =
                                &mul(dest.c1_a11_t_b20_m_b21, a11, c0_b20_m_b21);
                            let c1_a20_t_b10_p_b11 =
                                &mul(dest.c1_a20_t_b10_p_b11, a20, c0_b10_p_b11);
                            let c1_a21_t_b10_m_b11 =
                                &mul(dest.c1_a21_t_b10_m_b11, a21, c0_b10_m_b11);

                            let c1_p_a01_t_b00 =
                                &add(dest.c1_p_a01_t_b00, c1_a00_t_b01, c1_a01_t_b00);
                            let c1_p_a10_t_b20_p_b21 = &add(
                                dest.c1_p_a10_t_b20_p_b21,
                                c1_p_a01_t_b00,
                                c1_a10_t_b20_p_b21,
                            );
                            let c1_p_a11_t_b20_m_b21 = &add(
                                dest.c1_p_a11_t_b20_m_b21,
                                c1_p_a10_t_b20_p_b21,
                                c1_a11_t_b20_m_b21,
                            );
                            let c1_p_a20_t_b10_p_b11 = &add(
                                dest.c1_p_a20_t_b10_p_b11,
                                c1_p_a11_t_b20_m_b21,
                                c1_a20_t_b10_p_b11,
                            );
                            let c1 = &add(dest.c1, c1_p_a20_t_b10_p_b11, c1_a21_t_b10_m_b11);

                            (c0, c1)
                        };

                        let fp12_add = |dest: Fp6AddCols<F>, a: [&BigUint; 6], b: [&BigUint; 6]| {
                            let a00 = a[0];
                            let a01 = a[1];
                            let a10 = a[2];
                            let a11 = a[3];
                            let a20 = a[4];
                            let a21 = a[5];

                            let b00 = b[0];
                            let b01 = b[1];
                            let b10 = b[2];
                            let b11 = b[3];
                            let b20 = b[4];
                            let b21 = b[5];

                            let a00_p_b00 = &add(dest.a00_p_b00, a00, b00);
                            let a01_p_b01 = &add(dest.a01_p_b01, a01, b01);
                            let a10_p_b10 = &add(dest.a10_p_b10, a10, b10);
                            let a11_p_b11 = &add(dest.a11_p_b11, a11, b11);
                            let a20_p_b20 = &add(dest.a20_p_b20, a20, b20);
                            let _a21_p_b21 = &add(dest.a21_p_b21, a21, b21);
                        };

                        let fp12_mul_by_non_residue =
                            |dest: Fp6MulByNonResidue<F>, a: [&BigUint; 6]| {
                                let a00 = a[0];
                                let a01 = a[1];
                                let a10 = a[2];
                                let a11 = a[3];
                                let a20 = a[4];
                                let a21 = a[5];

                                let c00 = &sub(dest.c00, a20, a21);
                                let c01 = &add(dest.c01, a20, a21);

                                let c10 = a00;
                                let c11 = a01;

                                let c20 = a10;
                                let c21 = a11;
                            };

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

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        self.generate_trace(input, output);
    }

    fn preprocessed_width(&self) -> usize {
        0
    }

    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        None
    }
}
