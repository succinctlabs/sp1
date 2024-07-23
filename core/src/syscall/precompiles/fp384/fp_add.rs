use crate::air::{BaseAirBuilder, MachineAir, Polynomial, SP1AirBuilder};
use crate::bytes::event::ByteRecord;
use crate::memory::{value_as_limbs, MemoryReadCols, MemoryWriteCols};
use crate::operations::field::field_op::{FieldOpCols, FieldOperation};
use crate::operations::field::params::{FieldParameters, NumWords};
use crate::operations::field::params::{Limbs, NumLimbs};
use crate::operations::field::range::FieldRangeCols;
use crate::runtime::{ExecutionRecord, Program, Syscall, SyscallCode};
use crate::runtime::{MemoryReadRecord, MemoryWriteRecord};
use crate::stark::MachineRecord;
use crate::syscall::precompiles::SyscallContext;
use crate::utils::ec::weierstrass::bls12_381::Bls12381BaseField;
use crate::utils::{
    bytes_to_words_le, limbs_from_access, limbs_from_prev_access, pad_rows, words_to_bytes_le,
    words_to_bytes_le_vec,
};
use generic_array::GenericArray;
use itertools::Itertools;
use num::BigUint;
use num::Zero;
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

/// The number of columns in the FpAddCols.
const NUM_COLS: usize = size_of::<FpAddCols<u8>>();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpAddEvent {
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

#[derive(Default)]
pub struct FpAddChip<P> {
    _phantom: PhantomData<P>,
}

impl<P: FieldParameters> FpAddChip<P> {
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

type WordsFieldElement = <Bls12381BaseField as NumWords>::WordsFieldElement;
const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;

/// A set of columns for the FpAdd operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FpAddCols<T> {
    /// The shard number of the syscall.
    pub shard: T,

    /// The byte lookup channel.
    pub channel: T,

    /// The clock cycle of the syscall.
    pub clk: T,

    /// The nonce of the operation.
    pub nonce: T,

    /// The pointer to the first input.
    pub x_ptr: T,

    /// The pointer to the second input, which contains the y value.
    pub y_ptr: T,

    // Memory columns.
    // x_memory is written to with the result, which is why it is of type MemoryWriteCols.
    pub x_memory: GenericArray<MemoryWriteCols<T>, WordsFieldElement>,
    pub y_memory: GenericArray<MemoryReadCols<T>, WordsFieldElement>,

    // Output values. We compute (x + y) % modulus.
    pub output: FieldOpCols<T, Bls12381BaseField>,

    pub output_range_check: FieldRangeCols<T, Bls12381BaseField>,

    pub is_real: T,
}

impl<F: PrimeField32, P: FieldParameters> MachineAir<F> for FpAddChip<P> {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "FpAddMod".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows & corresponding records for each chunk of events concurrently.
        let rows_and_records = input
            .fp_add_events
            .chunks(1)
            .map(|events| {
                let mut records = ExecutionRecord::default();
                let mut new_byte_lookup_events = Vec::new();

                let rows = events
                    .iter()
                    .map(|event| {
                        let mut row: [F; NUM_COLS] = [F::zero(); NUM_COLS];
                        let cols: &mut FpAddCols<F> = row.as_mut_slice().borrow_mut();

                        // Decode uint384 points
                        let x = BigUint::from_bytes_le(&words_to_bytes_le::<48>(&event.x));
                        let y = BigUint::from_bytes_le(&words_to_bytes_le::<48>(&event.y));

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

                        // Populate the output column.
                        let effective_modulus = P::modulus();
                        let result = cols.output.populate_with_modulus(
                            &mut new_byte_lookup_events,
                            event.shard,
                            event.channel,
                            &x,
                            &y,
                            &effective_modulus,
                            FieldOperation::Add,
                        );

                        cols.output_range_check.populate(
                            &mut new_byte_lookup_events,
                            event.shard,
                            event.channel,
                            &result,
                            &effective_modulus,
                        );

                        row
                    })
                    .collect::<Vec<_>>();
                records.add_byte_lookup_events(new_byte_lookup_events);
                (rows, records)
            })
            .collect::<Vec<_>>();

        //  Generate the trace rows for each event.
        let mut rows = Vec::new();
        for (row, mut record) in rows_and_records {
            rows.extend(row);
            output.append(&mut record);
        }

        pad_rows(&mut rows, || {
            let mut row: [F; NUM_COLS] = [F::zero(); NUM_COLS];
            let cols: &mut FpAddCols<F> = row.as_mut_slice().borrow_mut();

            let x = BigUint::zero();
            let y = BigUint::zero();
            cols.output
                .populate(&mut vec![], 0, 0, &x, &y, FieldOperation::Add);

            row
        });

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_COLS);

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut FpAddCols<F> =
                trace.values[i * NUM_COLS..(i + 1) * NUM_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.fp_add_events.is_empty()
    }
}

impl<P: FieldParameters> Syscall for FpAddChip<P> {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
        let clk = rt.clk;
        let x_ptr = arg1;
        if x_ptr % 4 != 0 {
            panic!();
        }
        let y_ptr = arg2;
        if y_ptr % 4 != 0 {
            panic!();
        }

        // First read the words for the x value. We can read a slice_unsafe here because we write
        // the computed result to x later.
        let x = rt.slice_unsafe(x_ptr, WORDS_FIELD_ELEMENT);

        // Read the y value.
        let (y_memory_records, y) = rt.mr_slice(y_ptr, WORDS_FIELD_ELEMENT);

        // Get the BigUint values for x, y, and the modulus.
        let uint384_x = BigUint::from_bytes_le(&words_to_bytes_le_vec(&x));
        let uint384_y = BigUint::from_bytes_le(&words_to_bytes_le_vec(&y));

        // Perform the addition and take the result modulo the modulus.
        let modulus = Bls12381BaseField::modulus();
        let result: BigUint = (uint384_x + uint384_y) % modulus;

        let mut result_bytes = result.to_bytes_le();
        result_bytes.resize(48, 0u8); // Pad the result to 48 bytes.
                                      // Convert the result to little endian u32 words.
        let result = bytes_to_words_le::<12>(&result_bytes);

        rt.clk += 1;

        // Write the result to x and keep track of the memory records.
        let x_memory_records = rt.mw_slice(x_ptr, &result);

        let lookup_id = rt.syscall_lookup_id as usize;
        let shard = rt.current_shard();
        let channel = rt.current_channel();
        rt.record_mut().fp_add_events.push(FpAddEvent {
            lookup_id,
            shard,
            channel,
            clk,
            x_ptr,
            x,
            y_ptr,
            y,
            x_memory_records,
            y_memory_records,
        });

        None
    }
}

impl<F, P: FieldParameters> BaseAir<F> for FpAddChip<P> {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

impl<AB, P> Air<AB> for FpAddChip<P>
where
    AB: SP1AirBuilder,
    Limbs<AB::Var, <Bls12381BaseField as NumLimbs>::Limbs>: Copy,
    P: FieldParameters,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &FpAddCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &FpAddCols<AB::Var> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        // We are computing (x + y) % modulus. The value of x is stored in the "prev_value" of
        // the x_memory, since we write to it later.
        let x_limbs = limbs_from_prev_access(&local.x_memory);
        let y_limbs = limbs_from_access(&local.y_memory);

        // If the modulus is zero, then we don't perform the modulus operation.
        // Evaluate the modulus_is_zero operation by summing each byte of the modulus. The sum will
        // not overflow because we are summing 32 bytes.
        // If the modulus is zero, we'll actually use 2^384 as the modulus, so nothing happens.
        // Otherwise, we use the modulus passed in.
        let modulus_coeffs = P::MODULUS
            .iter()
            .map(|&limbs| AB::Expr::from_canonical_u8(limbs))
            .collect_vec();

        let p_modulus = Polynomial::from_coefficients(&modulus_coeffs);

        // Evaluate the uint384 addition
        local.output.eval_with_modulus(
            builder,
            &x_limbs,
            &y_limbs,
            &p_modulus,
            FieldOperation::Add,
            local.shard,
            local.channel,
            local.is_real,
        );

        // Verify the range of the output if the moduls is not zero.  Also, check the value of
        // modulus_is_not_zero.
        local.output_range_check.eval(
            builder,
            &local.output.result,
            &p_modulus,
            local.shard,
            local.channel,
            local.is_real,
        );

        // Assert that the correct result is being written to x_memory.
        builder
            .when(local.is_real)
            .assert_all_eq(local.output.result, value_as_limbs(&local.x_memory));

        // Read and write x.
        builder.eval_memory_access_slice(
            local.shard,
            local.channel,
            local.clk.into() + AB::Expr::one(),
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
            &local.y_memory,
            local.is_real,
        );

        // Receive the arguments.
        builder.receive_syscall(
            local.shard,
            local.channel,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::BLS12381_FPADD.syscall_id()),
            local.x_ptr,
            local.y_ptr,
            local.is_real,
        );

        // Assert that is_real is a boolean.
        builder.assert_bool(local.is_real);
    }
}
