use crate::{
    memory::{value_as_limbs, MemoryReadCols, MemoryWriteCols},
    operations::field::field_op::FieldOpCols,
};

use sp1_core_executor::{
    events::{ByteRecord, FieldOperation, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};

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

const NUM_COLS: usize = size_of::<AddMulChipCols<u8>>();

// This defines a type alias that gets the number of words needed to represent
// a field element in U256Field
type WordsFieldElement = <U256Field as NumWords>::WordsFieldElement;

// This creates a constant that holds the actual numeric value
const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;

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
    pub a_ptr: T,
    pub b_ptr: T,
    pub c_ptr: T,
    pub d_ptr: T,

    // Memory columns for reading inputs
    pub a_memory: GenericArray<MemoryReadCols<T>, WordsFieldElement>,
    pub b_memory: GenericArray<MemoryReadCols<T>, WordsFieldElement>,
    pub c_memory: GenericArray<MemoryReadCols<T>, WordsFieldElement>,
    pub d_memory: GenericArray<MemoryReadCols<T>, WordsFieldElement>,

    // First multiplication: a * b
    pub mul1_output: FieldOpCols<T, U256Field>,
    pub mul1_range_check: FieldLtCols<T, U256Field>,

    // Second multiplication: c * d
    pub mul2_output: FieldOpCols<T, U256Field>,
    pub mul2_range_check: FieldLtCols<T, U256Field>,

    // Final addition: (a*b) + (c*d)
    pub final_output: FieldOpCols<T, U256Field>,
    pub final_range_check: FieldLtCols<T, U256Field>,

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
            .get_precompile_events(SyscallCode::ADD_MUL)
            .chunks(1)
            .map(|events| {
                let mut records = ExecutionRecord::default();
                let mut new_byte_lookup_events = Vec::new();

                let rows = events
                    .iter()
                    .map(|(_, event)| {
                        let event = if let PrecompileEvent::AddMul(event) = event {
                            event
                        } else {
                            unreachable!()
                        };
                        let mut row: [F; NUM_COLS] = [F::zero(); NUM_COLS];
                        let cols: &mut AddMulChipCols<F> = row.as_mut_slice().borrow_mut();

                        // Decode inputs from bytes to BigUint
                        let a = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.a));
                        let b = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.b));
                        let c = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.c));
                        let d = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.d));

                        // Assign basic values
                        cols.is_real = F::one();
                        cols.shard = F::from_canonical_u32(event.shard);
                        cols.clk = F::from_canonical_u32(event.clk);
                        cols.a_ptr = F::from_canonical_u32(event.a_ptr);
                        cols.b_ptr = F::from_canonical_u32(event.b_ptr);
                        cols.c_ptr = F::from_canonical_u32(event.c_ptr);
                        cols.d_ptr = F::from_canonical_u32(event.d_ptr);

                        // Populate memory columns
                        for i in 0..WORDS_FIELD_ELEMENT {
                            cols.a_memory[i]
                                .populate(event.a_memory_records[i], &mut new_byte_lookup_events);
                            cols.b_memory[i]
                                .populate(event.b_memory_records[i], &mut new_byte_lookup_events);
                            cols.c_memory[i]
                                .populate(event.c_memory_records[i], &mut new_byte_lookup_events);
                            cols.d_memory[i]
                                .populate(event.d_memory_records[i], &mut new_byte_lookup_events);
                        }

                        // First multiplication (a * b)
                        let mul1_result = cols.mul1_output.populate(
                            &mut new_byte_lookup_events,
                            event.shard,
                            &a,
                            &b,
                            FieldOperation::Mul,
                        );

                        cols.mul1_range_check.populate(
                            &mut new_byte_lookup_events,
                            event.shard,
                            &mul1_result,
                            &(BigUint::one() << 256), // Check against 2^256
                        );

                        // Second multiplication (c * d)
                        let mul2_result = cols.mul2_output.populate(
                            &mut new_byte_lookup_events,
                            event.shard,
                            &c,
                            &d,
                            FieldOperation::Mul,
                        );

                        cols.mul2_range_check.populate(
                            &mut new_byte_lookup_events,
                            event.shard,
                            &mul2_result,
                            &(BigUint::one() << 256),
                        );

                        // Final addition ((a*b) + (c*d))
                        let final_result = cols.final_output.populate(
                            &mut new_byte_lookup_events,
                            event.shard,
                            &mul1_result,
                            &mul2_result,
                            FieldOperation::Add,
                        );

                        cols.final_range_check.populate(
                            &mut new_byte_lookup_events,
                            event.shard,
                            &final_result,
                            &(BigUint::one() << 256),
                        );

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
                let zero = BigUint::zero();
                cols.mul1_output.populate(&mut vec![], 0, &zero, &zero, FieldOperation::Mul);
                cols.mul2_output.populate(&mut vec![], 0, &zero, &zero, FieldOperation::Mul);
                cols.final_output.populate(&mut vec![], 0, &zero, &zero, FieldOperation::Add);

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
}


impl<F> BaseAir<F> for AddMulChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
}
