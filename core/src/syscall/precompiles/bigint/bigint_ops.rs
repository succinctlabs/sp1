use super::{U256Field, NUM_WORDS_IN_BIGUINT};
use crate::air::{MachineAir, SP1AirBuilder};
use crate::memory::{MemoryReadCols, MemoryWriteCols};
use crate::operations::field::field_op::{FieldOpCols, FieldOperation};
use crate::runtime::{ExecutionRecord, Register, Syscall};
use crate::runtime::{MemoryReadRecord, MemoryWriteRecord};
use crate::stark::MachineRecord;
use crate::syscall::precompiles::SyscallContext;
use crate::utils::{limbs_from_access, pad_rows};
use num::{BigUint, One};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use p3_maybe_rayon::prelude::{ParallelIterator, ParallelSlice};
use serde::{Deserialize, Serialize};
use sp1_derive::AlignedBorrow;
use std::borrow::{Borrow, BorrowMut};
use std::mem::size_of;

pub const NUM_BIGUINT_COLS: usize = size_of::<BigUintColumn<u8>>();

//***************************** Event ****************************/
//------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BigUintEvent {
    pub shard: u32,
    pub clk: u32,
    pub x_ptr: u32,
    pub x: [u32; NUM_WORDS_IN_BIGUINT],
    pub y_ptr: u32,
    pub y: [u32; NUM_WORDS_IN_BIGUINT],
    pub y_pointer_record: MemoryReadRecord,
    pub ops_ptr: u32,
    pub ops: u32,
    pub ops_pointer_record: MemoryReadRecord,
    pub ops_memory: MemoryReadRecord,
    pub x_memory_records: [MemoryWriteRecord; NUM_WORDS_IN_BIGUINT],
    pub y_memory_records: [MemoryReadRecord; NUM_WORDS_IN_BIGUINT],
}

//***************************** Chip ****************************/
//------------------------------------------------------------------------

#[derive(Default)]
pub struct BigUintChip;

impl BigUintChip {
    pub fn new() -> Self {
        Self
    }
}

//*****************************  Column ****************************/
//-----------------------------------------------------------------------

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct BigUintColumn<T> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub x_ptr: T,
    pub y_ptr: T,
    pub ops_ptr: T,

    // biguint operations
    pub is_add_op: T,
    pub is_sub_op: T,
    pub is_mul_op: T,

    // memory reads
    pub x_memory: [MemoryWriteCols<T>; NUM_WORDS_IN_BIGUINT],
    pub y_memory: [MemoryReadCols<T>; NUM_WORDS_IN_BIGUINT],
    pub ops_memory: MemoryReadCols<T>,
    pub y_ptr_access: MemoryReadCols<T>,
    pub ops_ptr_access: MemoryReadCols<T>,

    // input values for bigint operations
    pub x_input: [T; NUM_WORDS_IN_BIGUINT],
    pub y_input: [T; NUM_WORDS_IN_BIGUINT],

    // output values
    pub output: FieldOpCols<T>,
}

impl<F: PrimeField32> MachineAir<F> for BigUintChip {
    type Record = ExecutionRecord;

    fn name(&self) -> String {
        "BigUint".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // compute the number of events to process in each chunk.
        let chunk_size = std::cmp::max(input.biguint_events.len() / num_cpus::get(), 1);

        // Generate the trace rows & corresponding records for each chunk of events concurrently.
        let rows_and_records = input
            .biguint_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut records = ExecutionRecord::default();
                let mut new_field_events = Vec::new();

                let rows = events
                    .iter()
                    .map(|event| {
                        let mut row: [F; NUM_BIGUINT_COLS] = [F::zero(); NUM_BIGUINT_COLS];
                        let cols: &mut BigUintColumn<F> = row.as_mut_slice().borrow_mut();

                        // Decode biguint points
                        let x = biguint_from_words(&event.x);
                        let y = biguint_from_words(&event.y);

                        // Assign basic values to the columns.
                        {
                            cols.is_real = F::one();
                            cols.shard = F::from_canonical_u32(event.shard);
                            cols.clk = F::from_canonical_u32(event.clk);
                            cols.x_ptr = F::from_canonical_u32(event.x_ptr);
                            cols.y_ptr = F::from_canonical_u32(event.y_ptr);
                            cols.ops_ptr = F::from_canonical_u32(event.ops_ptr);
                        }
                        // Memory columns.
                        {
                            // Populate the columns with the input values
                            for i in 0..NUM_WORDS_IN_BIGUINT {
                                // populate the input_x columns
                                cols.x_memory[i]
                                    .populate(event.x_memory_records[i], &mut new_field_events);
                                // populate the input_y columns
                                cols.y_memory[i]
                                    .populate(event.y_memory_records[i], &mut new_field_events);
                            }
                            cols.y_ptr_access
                                .populate(event.y_pointer_record, &mut new_field_events);
                            cols.ops_ptr_access
                                .populate(event.ops_pointer_record, &mut new_field_events);
                            cols.ops_memory
                                .populate(event.ops_memory, &mut new_field_events);
                        }

                        // selector bits
                        {
                            match event.ops {
                                0 => {
                                    cols.is_add_op = F::one();
                                    cols.is_sub_op = F::zero();
                                    cols.is_mul_op = F::zero();

                                    cols.output
                                        .populate::<U256Field>(&x, &y, FieldOperation::Add);
                                }
                                1 => {
                                    cols.is_add_op = F::zero();
                                    cols.is_sub_op = F::one();
                                    cols.is_mul_op = F::zero();

                                    cols.output
                                        .populate::<U256Field>(&x, &y, FieldOperation::Sub);
                                }
                                2 => {
                                    cols.is_add_op = F::zero();
                                    cols.is_sub_op = F::zero();
                                    cols.is_mul_op = F::one();

                                    cols.output
                                        .populate::<U256Field>(&x, &y, FieldOperation::Mul);
                                }
                                _ => panic!("Invalid biguint operation"),
                            }
                        }

                        row
                    })
                    .collect::<Vec<_>>();
                records.add_field_events(&new_field_events);
                (rows, records)
            })
            .collect::<Vec<_>>();

        // Add the new field events to the output.
        let mut rows = Vec::new();
        for (row, record) in rows_and_records {
            rows.extend(row);
            output.add_field_events(&record.field_events);
        }

        pad_rows(&mut rows, || [F::zero(); NUM_BIGUINT_COLS]);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BIGUINT_COLS,
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.biguint_events.is_empty()
    }
}

//************************ Syscall handling  ********************************
//------------------------------------------------------------------------------------

impl Syscall for BigUintChip {
    fn num_extra_cycles(&self) -> u32 {
        8
    }

    fn execute(&self, rt: &mut SyscallContext) -> u32 {
        // input x
        let a0 = crate::runtime::Register::X10;

        // input y
        let a1 = crate::runtime::Register::X11;

        // biguint operation to be executed
        let a2 = crate::runtime::Register::X12;

        let start_clk = rt.clk;

        // TODO: this will have to be be constrained, but can do it later.
        let x_ptr = rt.register_unsafe(a0);
        if x_ptr % 4 != 0 {
            panic!();
        }

        let (ops_ptr_record, ops_ptr) = rt.mr(a2 as u32);
        if ops_ptr % 4 != 0 {
            panic!();
        }

        let (y_ptr_record, y_ptr) = rt.mr(a1 as u32);
        if y_ptr % 4 != 0 {
            panic!();
        }

        let (ops_records, ops) = rt.mr(ops_ptr);

        let x: [u32; NUM_WORDS_IN_BIGUINT] = rt
            .slice_unsafe(x_ptr, NUM_WORDS_IN_BIGUINT)
            .try_into()
            .unwrap();

        let (y_memory_records_vec, y_vec) = rt.mr_slice(y_ptr, NUM_WORDS_IN_BIGUINT);
        let y_memory_records = y_memory_records_vec.try_into().unwrap();
        let y: [u32; NUM_WORDS_IN_BIGUINT] = y_vec.try_into().unwrap();

        let biguint_x = biguint_from_words(&x);
        let biguint_y = biguint_from_words(&y);

        // mask for 256 bits
        let mask = BigUint::one() << 256;

        println!("x: {:?}", biguint_x);
        println!("y: {:?}", biguint_y);
        println!("ops: {:?}", ops);
        // call the bigint function on the inputs
        let biguint_result = match ops {
            0 => (biguint_x + biguint_y) % mask,
            1 => (biguint_x - biguint_y) % mask,
            2 => (biguint_x * biguint_y) % mask,
            _ => panic!("Invalid bigint operation"),
        };

        // increment the clock as we are writing to the state.
        rt.clk += 4;

        let result = biguint_to_words(&biguint_result);

        // write the state
        let state_memory_records = rt.mw_slice(x_ptr, &result).try_into().unwrap();

        // increment the clock.
        rt.clk += 4;

        let shard = rt.current_shard();

        rt.record_mut().biguint_events.push(BigUintEvent {
            shard,
            clk: start_clk,
            x_ptr,
            x,
            y_ptr,
            y,
            y_pointer_record: y_ptr_record,
            ops_ptr,
            ops,
            ops_pointer_record: ops_ptr_record,
            ops_memory: ops_records,
            x_memory_records: state_memory_records,
            y_memory_records,
        });

        x_ptr + 1
    }
}

//****************************** AIR  ****************************************/
//-----------------------------------------------------------------------------

impl<F> BaseAir<F> for BigUintChip {
    fn width(&self) -> usize {
        NUM_BIGUINT_COLS
    }
}

impl<AB> Air<AB> for BigUintChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &BigUintColumn<AB::Var> = main.row_slice(0).borrow();

        let x = limbs_from_access(&local.x_memory);
        let y = limbs_from_access(&local.y_memory);

        let is_add = local.is_add_op;
        let is_sub = local.is_sub_op;
        let is_mul = local.is_mul_op;
        let is_real = local.is_real;

        // assert that is_add, is_sub, is_mul are mutually exclusive and boolean
        builder.assert_bool(is_add);
        builder.assert_bool(is_sub);
        builder.assert_bool(is_mul);
        builder.assert_bool(is_real);

        // assert that exactly one of is_add, is_sub, is_mul is set to 1
        let sum: AB::Expr = is_add.into() + is_sub.into() + is_mul.into();
        builder
            .when(is_real)
            .assert_eq(sum, AB::F::from_canonical_usize(1));

        let is_add_builder = builder.when(is_add);
        let is_sub_builder = builder.when(is_sub);
        let is_mul_builder = builder.when(is_mul);

        // local
        //     .output
        //     .eval::<AB, U256Field, _, _>(is_add_builder, &x, &y, FieldOperation::Add);
        // local
        //     .output
        //     .eval::<AB, U256Field, _, _>(is_sub_builder, &x, &y, FieldOperation::Sub);
        // local
        //     .output
        //     .eval::<AB, U256Field, _, _>(is_mul_builder, &x, &y, FieldOperation::Mul);

        // constrain the memory reads
        builder.constraint_memory_access(
            local.shard,
            local.clk,
            AB::F::from_canonical_u32(Register::X12 as u32),
            &local.ops_ptr_access,
            local.is_real,
        );
        builder.constraint_memory_access(
            local.shard,
            local.clk,
            local.ops_ptr,
            &local.ops_memory,
            local.is_real,
        );
        builder.constraint_memory_access(
            local.shard,
            local.clk,
            AB::F::from_canonical_u32(Register::X11 as u32),
            &local.y_ptr_access,
            local.is_real,
        );
        builder.constraint_memory_access_slice(
            local.shard,
            local.clk.into(),
            local.y_ptr,
            &local.y_memory,
            local.is_real,
        );

        builder.constraint_memory_access_slice(
            local.shard,
            local.clk + AB::F::from_canonical_u32(4),
            local.x_ptr,
            &local.x_memory,
            is_real,
        );
    }
}

//****************************** HELPER METHODS *******************************
//-----------------------------------------------------------------------------

// Convert a vector of u32 words into a BigUint
fn biguint_from_words(words: &[u32]) -> BigUint {
    let bytes = words
        .iter()
        .flat_map(|n| n.to_le_bytes())
        .collect::<Vec<_>>();
    BigUint::from_bytes_le(bytes.as_slice())
}

// Convert a BigUint into a vector of u32 words
fn biguint_to_words(value: &BigUint) -> [u32; NUM_WORDS_IN_BIGUINT] {
    let mut bytes = value.to_bytes_le();
    bytes.resize(NUM_WORDS_IN_BIGUINT * 4, 0u8);

    let mut words = [0u32; NUM_WORDS_IN_BIGUINT];
    bytes
        .chunks_exact(4)
        .enumerate()
        .for_each(|(i, chunk)| words[i] = u32::from_le_bytes(chunk.try_into().unwrap()));
    words
}
