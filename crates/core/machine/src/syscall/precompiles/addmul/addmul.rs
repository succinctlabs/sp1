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
    pub a: T,
    pub b: T,
    pub c: T,
    pub d: T,

    pub a_ptr: T,
    // pub b_ptr: T,
    // pub c_ptr: T,
    // pub d_ptr: T,

    // First multiplication: a * b
    pub mul1_output: T,
    // pub mul1_range_check: FieldLtCols<T, U32>,

    // Second multiplication: c * d
    pub mul2_output: T,
    // pub mul2_range_check: FieldLtCols<T, U32>,

    // Final addition: (a*b) + (c*d)
    pub final_output: T,
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
                        println!("NUM_COLS: {}", NUM_COLS);
                        let mut row: [F; NUM_COLS] = [F::zero(); NUM_COLS];
                        let cols: &mut AddMulChipCols<F> = row.as_mut_slice().borrow_mut();
                        // Assign basic values
                        cols.is_real = F::one();
                        cols.shard = F::from_canonical_u32(event.shard);
                        cols.clk = F::from_canonical_u32(event.clk);
                        cols.a_ptr = F::from_canonical_u32(event.a_ptr);
                        // cols.b_ptr = F::from_canonical_u32(event.b_ptr);
                        // cols.c_ptr = F::from_canonical_u32(event.c_ptr);
                        // cols.d_ptr = F::from_canonical_u32(event.d_ptr);

                        cols.a = F::from_canonical_u32(event.a);
                        cols.b = F::from_canonical_u32(event.b);
                        cols.c = F::from_canonical_u32(event.c);
                        cols.d = F::from_canonical_u32(event.d);
                        cols.mul1_output = cols.a * cols.b;
                        cols.mul2_output = cols.c * cols.d;
                        cols.final_output = cols.mul1_output + cols.mul2_output;
                        
                        for (i, value) in row.iter().enumerate() {
                            println!("Column {}: {:?}", i, value);
                        }
                        row
                    })
                    .collect::<Vec<_>>();
                records.add_byte_lookup_events(new_byte_lookup_events);
                (rows, records)
            })
            .collect::<Vec<_>>();

        // Collect all rows
        let mut rows = Vec::new();
        println!("rows_and_records: {:?}", rows_and_records);
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
                let zero: F = F::zero();
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
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &AddMulChipCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &AddMulChipCols<AB::Var> = (*next).borrow();

        builder.assert_bool(local.is_real);
        builder.receive_syscall(
            local.shard,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::ADDMUL.syscall_id()),
            local.a_ptr,
            local.a_ptr,
            local.is_real,
            InteractionScope::Local,
        );
        // Perform the addmul operation and assert the result
        // 1. Basic boolean and nonce constraints
        
        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        builder.assert_eq(local.mul1_output, local.a * local.b);
        builder.assert_eq(local.mul2_output, local.c * local.d);
        builder.assert_eq(local.final_output, local.mul1_output + local.mul2_output);

    }
}