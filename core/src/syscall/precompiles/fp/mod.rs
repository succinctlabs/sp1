use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use num::{BigUint, One, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use serde::{Deserialize, Serialize};
use sp1_derive::AlignedBorrow;

use crate::{
    air::{BaseAirBuilder, MachineAir, Polynomial, WORD_SIZE},
    bytes::event::ByteRecord,
    memory::{value_as_limbs, MemoryReadCols, MemoryWriteCols},
    operations::{
        field::{
            field_op::{FieldOpCols, FieldOperation},
            params::{Limbs, NumLimbs, NumWords},
        },
        IsZeroOperation,
    },
    runtime::{
        ExecutionRecord, MemoryReadRecord, MemoryWriteRecord, Program, Syscall, SyscallCode,
        SyscallContext,
    },
    stark::{MachineRecord, SP1AirBuilder},
    utils::{
        bytes_to_words_le, ec::uint::U384Field, limbs_from_access, limbs_from_prev_access,
        pad_rows, words_to_bytes_le, words_to_bytes_le_vec,
    },
};
use generic_array::GenericArray;
use typenum::Unsigned;

const NUM_COLS: usize = size_of::<Fp384AddCols<u8>>();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fp384AddEvent {
    pub shard: u32,
    pub clk: u32,
    pub channel: u32,
    pub x: Vec<u32>,
    pub x_ptr: u32,
    pub y: Vec<u32>,
    pub y_ptr: u32,
    pub modulus: Vec<u32>,
    pub x_memory_records: Vec<MemoryWriteRecord>,
    pub y_memory_records: Vec<MemoryReadRecord>,
    pub modulus_memory_records: Vec<MemoryReadRecord>,
}

#[derive(Default)]
pub struct Fp384AddChip;

impl Fp384AddChip {
    pub const fn new() -> Self {
        Self
    }
}

type WordsFieldElement = <U384Field as NumWords>::WordsFieldElement;
const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Fp384AddCols<T> {
    pub is_real: T,
    pub shard: T,
    pub nonce: T,
    pub clk: T,
    pub channel: T,
    pub x_ptr: T,
    pub y_ptr: T,
    pub x_access: GenericArray<MemoryWriteCols<T>, WordsFieldElement>,
    pub y_access: GenericArray<MemoryWriteCols<T>, WordsFieldElement>,
    pub modulus_is_zero: IsZeroOperation<T>,

    // Memory columns.
    // x_memory is written to with the result, which is why it is of type MemoryWriteCols.
    pub x_memory: GenericArray<MemoryWriteCols<T>, WordsFieldElement>,
    pub y_memory: GenericArray<MemoryReadCols<T>, WordsFieldElement>,
    pub modulus_memory: GenericArray<MemoryReadCols<T>, WordsFieldElement>,

    pub output: FieldOpCols<T, U384Field>,
}

impl<F: PrimeField32> MachineAir<F> for Fp384AddChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Fp384Add".to_string()
    }

    fn generate_trace(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
    ) -> p3_matrix::dense::RowMajorMatrix<F> {
        let rows_and_records = input
            .fp384_add_events
            .chunks(1)
            .map(|events| {
                let mut records = ExecutionRecord::default();
                let mut new_byte_lookup_events = Vec::new();

                let rows = events
                    .iter()
                    .map(|event| {
                        let mut row: [F; NUM_COLS] = [F::zero(); NUM_COLS];
                        let cols: &mut Fp384AddCols<F> = row.as_mut_slice().borrow_mut();

                        let x = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.x));
                        let y = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.y));
                        let modulus =
                            BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.modulus));

                        cols.is_real = F::one();
                        cols.shard = F::from_canonical_u32(event.shard);
                        cols.clk = F::from_canonical_u32(event.clk);
                        cols.x_ptr = F::from_canonical_u32(event.x_ptr);
                        cols.y_ptr = F::from_canonical_u32(event.y_ptr);

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
                            cols.modulus_memory[i].populate(
                                event.channel,
                                event.modulus_memory_records[i],
                                &mut new_byte_lookup_events,
                            );
                        }

                        let modulus_bytes = words_to_bytes_le_vec(&event.modulus);
                        let modulus_byte_sum = modulus_bytes.iter().map(|b| *b as u32).sum::<u32>();
                        IsZeroOperation::populate(&mut cols.modulus_is_zero, modulus_byte_sum);

                        let effective_modulus = if modulus.is_zero() {
                            BigUint::one() << 384
                        } else {
                            modulus.clone()
                        };

                        cols.output.populate_with_modulus(
                            &mut new_byte_lookup_events,
                            event.shard,
                            event.channel,
                            &x,
                            &y,
                            &effective_modulus,
                            FieldOperation::Add,
                        );

                        row
                    })
                    .collect::<Vec<_>>();
                records.add_byte_lookup_events(new_byte_lookup_events);
                (rows, records)
            })
            .collect::<Vec<_>>();

        let mut rows = Vec::new();
        for (row, mut record) in rows_and_records {
            rows.extend(row);
            output.append(&mut record);
        }

        pad_rows(&mut rows, || {
            let mut row: [F; NUM_COLS] = [F::zero(); NUM_COLS];
            let cols: &mut Fp384AddCols<F> = row.as_mut_slice().borrow_mut();

            let x = BigUint::zero();
            let y = BigUint::zero();
            cols.output
                .populate(&mut vec![], 0, 0, &x, &y, FieldOperation::Add);

            row
        });

        let mut trace = RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_COLS);

        for i in 0..trace.height() {
            let cols: &mut Fp384AddCols<F> =
                trace.values[i * NUM_COLS..(i + 1) * NUM_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.fp384_add_events.is_empty()
    }
}

impl Syscall for Fp384AddChip {
    fn num_extra_cycles(&self) -> u32 {
        0
    }

    fn execute(&self, rt: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
        let x_ptr = arg1;
        if x_ptr % 4 != 0 {
            panic!();
        }
        let y_ptr = arg2;
        if y_ptr % 4 != 0 {
            panic!();
        }

        let x = rt.slice_unsafe(x_ptr, WORDS_FIELD_ELEMENT);
        let (y_memory_records, y) = rt.mr_slice(y_ptr, WORDS_FIELD_ELEMENT);
        let modulus_ptr = y_ptr + WORDS_FIELD_ELEMENT as u32 * WORD_SIZE as u32;
        let (modulus_memory_records, modulus) = rt.mr_slice(modulus_ptr, WORDS_FIELD_ELEMENT);

        let fp384_x = BigUint::from_bytes_le(&words_to_bytes_le_vec(&x));
        let fp384_y = BigUint::from_bytes_le(&words_to_bytes_le_vec(&y));
        let fp384_modulus = BigUint::from_bytes_le(&words_to_bytes_le_vec(&modulus));

        let result: BigUint = if fp384_modulus.is_zero() {
            (fp384_x + fp384_y) % (BigUint::one() << 384)
        } else {
            (fp384_x + fp384_y) % fp384_modulus
        };

        let mut result_bytes = result.to_bytes_le();
        result_bytes.resize(32, 0u8);

        let result = bytes_to_words_le::<8>(&result_bytes);
        let x_memory_records = rt.mw_slice(x_ptr, &result);

        let lookup_id = rt.syscall_lookup_id;
        let shard = rt.current_shard();
        let channel = rt.current_channel();
        let clk = rt.clk;
        rt.record_mut().fp384_add_events.push(Fp384AddEvent {
            shard,
            clk,
            channel,
            x,
            x_ptr,
            y,
            y_ptr,
            modulus,
            x_memory_records,
            y_memory_records,
            modulus_memory_records,
        });

        None
    }
}

impl<F> BaseAir<F> for Fp384AddChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

impl<AB> Air<AB> for Fp384AddChip
where
    AB: SP1AirBuilder,
    Limbs<AB::Var, <U384Field as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Fp384AddCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &Fp384AddCols<AB::Var> = (*next).borrow();

        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        let x_limbs = limbs_from_prev_access(&local.x_memory);
        let y_limbs = limbs_from_access(&local.y_memory);
        let modulus_limbs = limbs_from_access(&local.modulus_memory);

        let modulus_byte_sum = modulus_limbs
            .0
            .iter()
            .fold(AB::Expr::zero(), |acc, &limb| acc + limb);
        IsZeroOperation::<AB::F>::eval(
            builder,
            modulus_byte_sum,
            local.modulus_is_zero,
            local.is_real.into(),
        );

        let modulus_is_zero = local.modulus_is_zero.result;
        let mut coeff_2_256 = Vec::new();
        coeff_2_256.resize(48, AB::Expr::zero());
        coeff_2_256.push(AB::Expr::one());
        let modulus_polynomial: Polynomial<AB::Expr> = modulus_limbs.into();
        let p_modulus: Polynomial<AB::Expr> = modulus_polynomial
            * (AB::Expr::one() - modulus_is_zero.into())
            + Polynomial::from_coefficients(&coeff_2_256) * modulus_is_zero.into();

        local.output.eval_with_modulus(
            builder,
            &x_limbs,
            &y_limbs,
            &p_modulus,
            FieldOperation::Mul,
            local.shard,
            local.channel,
            local.is_real,
        );

        builder
            .when(local.is_real)
            .assert_all_eq(local.output.result, value_as_limbs(&local.x_memory));

        // Read and write x.
        builder.eval_memory_access_slice(
            local.shard,
            local.channel,
            local.clk.into(),
            local.x_ptr,
            &local.x_memory,
            local.is_real,
        );

        // Evaluate the y_ptr memory access. We concatenate y and modulus into a single array since
        // we read it contiguously from the y_ptr memory location.
        builder.eval_memory_access_slice(
            local.shard,
            local.channel,
            local.clk.into(),
            local.y_ptr,
            &[local.y_memory, local.modulus_memory].concat(),
            local.is_real,
        );

        // Receive the arguments.
        builder.receive_syscall(
            local.shard,
            local.channel,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::FP384_ADD.syscall_id()),
            local.x_ptr,
            local.y_ptr,
            local.is_real,
        );

        // Assert that is_real is a boolean.
        builder.assert_bool(local.is_real);
    }
}
