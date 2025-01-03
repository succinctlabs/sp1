use crate::{
    memory::{value_as_limbs, MemoryReadCols, MemoryWriteCols},
    operations::field::field_op::FieldOpCols,
};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::MachineAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_air::BaseAir;
use sp1_stark::air::SP1AirBuilder;
use sp1_stark::air::InteractionScope;
use p3_air::Air;
use p3_field::AbstractField;
use p3_matrix::Matrix;
use p3_air::AirBuilder;
use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use sp1_core_executor::{
    events::{ByteRecord, FieldOperation, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};

use typenum::{U32};
use num::{BigUint, Zero};

use crate::{
    air::MemoryAirBuilder,
    operations::{field::range::FieldLtCols, IsZeroOperation},
    utils::{
        limbs_from_access, limbs_from_prev_access, pad_rows_fixed, words_to_bytes_le,
        words_to_bytes_le_vec,
    },
};

use sp1_curves::{
    params::{Limbs, NumLimbs, NumWords},
    uint256::U256Field,
};

use sp1_stark::MachineRecord;

const NUM_COLS: usize = size_of::<AddMulChipCols<u32>>();


// // This defines a type alias that gets the number of words needed to represent
// // a field element in U256Field
// type WordsFieldElement = <U256Field as NumWords>::WordsFieldElement;

// // This creates a constant that holds the actual numeric value
// const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;

#[derive(Default)]
pub struct AddMulChip;

impl AddMulChip {
    pub const fn new() -> Self {
        Self
    }

}

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct AddMulChipCols<T> {
    /// The shard number of the operation
    pub shard: T,

    /// The clock cycle
    pub clk: T,

    /// Unique identifier for this operation
    pub nonce: T,

    // Memory pointers for inputs
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,

    pub a_ptr: T,
    pub b_ptr: T,
    pub c_ptr: T,
    pub d_ptr: T,

    // First multiplication: a * b
    pub mul1_output: u32,
    // pub mul1_range_check: FieldLtCols<T, U32>,

    // Second multiplication: c * d
    pub mul2_output: u32,
    // pub mul2_range_check: FieldLtCols<T, U32>,

    // Final addition: (a*b) + (c*d)
    pub final_output: u32,
    // pub final_range_check: FieldLtCols<T, U32>,

    // Flag to indicate if this is a real operation
    pub is_real: T,
}

impl<F: PrimeField32> MachineAir<F> for AddMulChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "AddMul".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate trace rows for each event
        let rows_and_records = input
            .get_precompile_events(SyscallCode::ADDMUL)
            .chunks(1)
            .map(|events| {
                let mut records = ExecutionRecord::default();
                let mut new_byte_lookup_events = Vec::new();

                let rows = events
                    .iter()
                    .map(|(_, event)| {
                        let event = if let PrecompileEvent::ADDMul(event) = event {
                            event
                        } else {
                            unreachable!()
                        };
                        let mut row: [F; NUM_COLS] = [F::zero(); NUM_COLS];
                        let cols: &mut AddMulChipCols<F> = row.as_mut_slice().borrow_mut();


                        // Assign basic values
                        cols.is_real = F::one();
                        cols.shard = F::from_canonical_u32(event.shard);
                        cols.clk = F::from_canonical_u32(event.clk);
                        cols.a_ptr = F::from_canonical_u32(event.a_ptr);
                        cols.b_ptr = F::from_canonical_u32(event.b_ptr);
                        cols.c_ptr = F::from_canonical_u32(event.c_ptr);
                        cols.d_ptr = F::from_canonical_u32(event.d_ptr);

                        cols.a = event.a;
                        cols.b = event.b;
                        cols.c = event.c;
                        cols.d = event.d;

                        // // Populate memory columns
                        // for i in 0..WORDS_FIELD_ELEMENT {
                        //     cols.a_memory[i]
                        //         .populate(event.a_memory_records[i], &mut new_byte_lookup_events);
                        //     cols.b_memory[i]
                        //         .populate(event.b_memory_records[i], &mut new_byte_lookup_events);
                        //     cols.c_memory[i]
                        //         .populate(event.c_memory_records[i], &mut new_byte_lookup_events);
                        //     cols.d_memory[i]
                        //         .populate(event.d_memory_records[i], &mut new_byte_lookup_events);
                        // }

                        // First multiplication (a * b)
                        let mul1_result = cols.a * cols.b;
                        cols.mul1_output = mul1_result;
                        // .populate(
                        //     &mut new_byte_lookup_events,
                        //     event.shard,
                        //     &cols.a,
                        //     &cols.b,
                        //     FieldOperation::Mul,
                        // );

                        // cols.mul1_range_check.populate(
                        //     &mut new_byte_lookup_events,
                        //     event.shard,
                        //     &mul1_result,
                        //     &(BigUint::one() << 256), // Check against 2^256
                        // );

                        // Second multiplication (c * d)
                        // let mul2_result = cols.mul2_output.populate(
                        //     &mut new_byte_lookup_events,
                        //     event.shard,
                        //     &cols.c,
                        //     &cols.d,
                        //     FieldOperation::Mul,
                        // );
                        let mul2_result = cols.c * cols.d;
                        cols.mul2_output = mul2_result;

                        // cols.mul2_range_check.populate(
                        //     &mut new_byte_lookup_events,
                        //     event.shard,
                        //     &mul2_result,
                        //     &(BigUint::one() << 256),
                        // );

                        // Final addition ((a*b) + (c*d))
                        // let final_result = cols.final_output.populate(
                        //     &mut new_byte_lookup_events,
                        //     event.shard,
                        //     &mul1_result,
                        //     &mul2_result,
                        //     FieldOperation::Add,
                        // );
                        let final_result = mul1_result + mul2_result;
                        cols.final_output = final_result;

                        // cols.final_range_check.populate(
                        //     &mut new_byte_lookup_events,
                        //     event.shard,
                        //     &final_result,
                        //     &(BigUint::one() << 256),
                        // );

                        row
                    })
                    .collect::<Vec<_>>();
                records.add_byte_lookup_events(new_byte_lookup_events);
                (rows, records)
            })
            .collect::<Vec<_>>();

        // Collect all rows
        let mut rows = Vec::new();
        for (row, mut record) in rows_and_records {
            rows.extend(row);
            output.append(&mut record);
        }

        // Pad rows to required size
        pad_rows_fixed(
            &mut rows,
            || {
                let mut row: [F; NUM_COLS] = [F::zero(); NUM_COLS];
                let cols: &mut AddMulChipCols<F> = row.as_mut_slice().borrow_mut();

                // Initialize empty computation for padding
                let zero: u32 = 0;
                cols.mul1_output = zero;
                cols.mul2_output = zero;
                cols.final_output = zero;

                row
            },
            input.fixed_log2_rows::<F, _>(self),
        );

        // Create matrix and add nonces
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_COLS
        );

        // Write nonces to trace
        for i in 0..trace.height() {
            let cols: &mut AddMulChipCols<F> =
                trace.values[i * NUM_COLS..(i + 1) * NUM_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::ADDMUL).is_empty()
        }
    }
}


impl<F> BaseAir<F> for AddMulChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

impl<AB> Air<AB> for AddMulChip
where
    AB: SP1AirBuilder,
    Limbs<AB::Var, <U256Field as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &AddMulChipCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &AddMulChipCols<AB::Var> = (*next).borrow();

        // 1. Basic boolean and nonce constraints
        builder.assert_bool(local.is_real);
        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        // 2. Memory access constraints for inputs
        // builder.eval_memory_access(
        //     local.shard,
        //     local.clk.into(),
        //     local.a_ptr,
        //     &local.a,
        //     local.is_real,
        // );
        // assert_eq!(rt.mr(local.a_ptr), local.a);
        // assert_eq!(rt.mr(local.b_ptr), local.b);
        // assert_eq!(rt.mr(local.c_ptr), local.c);
        // assert_eq!(rt.mr(local.d_ptr), local.d);
        // builder.eval_memory_access_slice(
        //     local.shard,
        //     local.clk.into(),
        //     local.a_ptr,
        //     &local.a,
        //     local.is_real,
        // );
        // builder.eval_memory_access_slice(
        //     local.shard,
        //     local.clk.into(),
        //     local.b_ptr,
        //     &local.b,
        //     local.is_real,
        // );
        // builder.eval_memory_access_slice(
        //     local.shard,
        //     local.clk.into(),
        //     local.c_ptr,
        //     &local.c,
        //     local.is_real,
        // );
        // builder.eval_memory_access_slice(
        //     local.shard,
        //     local.clk.into(),
        //     local.d_ptr,
        //     &local.d,
        //     local.is_real,
        // );
        // builder.eval_memory_access_slice(
        //     local.shard,
        //     local.clk.into(),
        //     local.b_ptr,
        //     &local.b_memory,
        //     local.is_real,
        // );
        // builder.eval_memory_access_slice(
        //     local.shard,
        //     local.clk.into(),
        //     local.c_ptr,
        //     &local.c_memory,
        //     local.is_real,
        // );
        // builder.eval_memory_access_slice(
        //     local.shard,
        //     local.clk.into(),
        //     local.d_ptr,
        //     &local.d_memory,
        //     local.is_real,
        // );

        // 3. First multiplication (a * b)
        // let a_limbs = limbs_from_access(&local.a_memory);
        // let b_limbs = limbs_from_access(&local.b_memory);
        // let modulus_2_256 = {
        //     let mut coeff = Vec::new();
        //     coeff.resize(32, AB::Expr::zero());
        //     coeff.push(AB::Expr::one());
        //     Polynomial::from_coefficients(&coeff)
        // };

        // Verify first multiplication
        assert_eq!(local.mul1_output, local.a * local.b);
        // local.mul1_output.eval(
        //     builder,
        //     &local.a,
        //     &local.b,
        //     // &modulus_2_256,
        //     FieldOperation::Mul,
        //     local.is_real,
        // );

        // Range check for mul1
        // local.mul1_range_check.eval(
        //     builder,
        //     &local.mul1_output.result,
        //     &limbs_from_polynomial(&modulus_2_256),
        //     local.is_real,
        // );

        // 4. Second multiplication (c * d)
        // let c_limbs = limbs_from_access(&local.c_memory);
        // let d_limbs = limbs_from_access(&local.d_memory);

        // Verify second multiplication
        assert_eq!(local.mul1_output, local.c * local.d);
        // local.mul2_output.eval(
        //     builder,
        //     &local.c,
        //     &local.d,
        //     // &modulus_2_256,
        //     FieldOperation::Mul,
        //     local.is_real,
        // );

        // Range check for mul2
        // local.mul2_range_check.eval(
        //     builder,
        //     &local.mul2_output.result,
        //     &limbs_from_polynomial(&modulus_2_256),
        //     local.is_real,
        // );

        // Final addition ((a*b) + (c*d))
        assert_eq!(local.final_output, local.mul1_output + local.mul2_output);
        // local.final_output.eval(
        //     builder,
        //     &local.mul1_output.result,
        //     &local.mul2_output.result,
        //     // &modulus_2_256,
        //     FieldOperation::Add,
        //     local.is_real,
        // );

        // Range check for final result
        // local.final_range_check.eval(
        //     builder,
        //     &local.final_output.result,
        //     &limbs_from_polynomial(&modulus_2_256),
        //     local.is_real,
        // );

        // Syscall verification
        builder.receive_syscall(
            local.shard,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::ADDMUL.syscall_id()),
            local.a_ptr,  
            local.b_ptr, 
            local.is_real,
            InteractionScope::Local,
        );
    }
}