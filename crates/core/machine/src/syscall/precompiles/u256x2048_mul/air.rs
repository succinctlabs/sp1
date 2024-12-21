use crate::{
    air::MemoryAirBuilder,
    memory::{value_as_limbs, MemoryCols, MemoryReadCols, MemoryWriteCols},
    operations::field::field_op::FieldOpCols,
    utils::{limbs_from_access, pad_rows_fixed, words_to_bytes_le},
};

use num::{BigUint, One, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{
    events::{ByteRecord, FieldOperation, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program, Register,
};
use sp1_curves::{
    params::{NumLimbs, NumWords},
    uint256::U256Field,
};
use sp1_derive::AlignedBorrow;
use sp1_stark::{
    air::{BaseAirBuilder, InteractionScope, MachineAir, Polynomial, SP1AirBuilder},
    MachineRecord,
};
use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use typenum::Unsigned;

/// The number of columns in the U256x2048MulCols.
const NUM_COLS: usize = size_of::<U256x2048MulCols<u8>>();

#[derive(Default)]
pub struct U256x2048MulChip;

impl U256x2048MulChip {
    pub const fn new() -> Self {
        Self
    }
}
type WordsFieldElement = <U256Field as NumWords>::WordsFieldElement;
const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;
const LO_REGISTER: u32 = Register::X12 as u32;
const HI_REGISTER: u32 = Register::X13 as u32;

/// A set of columns for the U256x2048Mul operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct U256x2048MulCols<T> {
    /// The shard number of the syscall.
    pub shard: T,

    /// The clock cycle of the syscall.
    pub clk: T,

    /// The pointer to the first input.
    pub a_ptr: T,

    /// The pointer to the second input.
    pub b_ptr: T,

    pub lo_ptr: T,
    pub hi_ptr: T,

    pub lo_ptr_memory: MemoryReadCols<T>,
    pub hi_ptr_memory: MemoryReadCols<T>,

    // Memory columns.
    pub a_memory: [MemoryReadCols<T>; WORDS_FIELD_ELEMENT],
    pub b_memory: [MemoryReadCols<T>; WORDS_FIELD_ELEMENT * 8],
    pub lo_memory: [MemoryWriteCols<T>; WORDS_FIELD_ELEMENT * 8],
    pub hi_memory: [MemoryWriteCols<T>; WORDS_FIELD_ELEMENT],

    // Output values. We compute (x * y) % 2^2048 and (x * y) / 2^2048.
    pub a_mul_b1: FieldOpCols<T, U256Field>,
    pub ab2_plus_carry: FieldOpCols<T, U256Field>,
    pub ab3_plus_carry: FieldOpCols<T, U256Field>,
    pub ab4_plus_carry: FieldOpCols<T, U256Field>,
    pub ab5_plus_carry: FieldOpCols<T, U256Field>,
    pub ab6_plus_carry: FieldOpCols<T, U256Field>,
    pub ab7_plus_carry: FieldOpCols<T, U256Field>,
    pub ab8_plus_carry: FieldOpCols<T, U256Field>,
    pub is_real: T,
}

impl<F: PrimeField32> MachineAir<F> for U256x2048MulChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "U256XU2048Mul".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Implement trace generation logic.
        let rows_and_records = input
            .get_precompile_events(SyscallCode::U256XU2048_MUL)
            .chunks(1)
            .map(|events| {
                let mut records = ExecutionRecord::default();
                let mut new_byte_lookup_events = Vec::new();

                let rows = events
                    .iter()
                    .map(|(_, event)| {
                        let event = if let PrecompileEvent::U256xU2048Mul(event) = event {
                            event
                        } else {
                            unreachable!()
                        };
                        let mut row: [F; NUM_COLS] = [F::zero(); NUM_COLS];
                        let cols: &mut U256x2048MulCols<F> = row.as_mut_slice().borrow_mut();

                        // Assign basic values to the columns.
                        cols.is_real = F::one();
                        cols.shard = F::from_canonical_u32(event.shard);
                        cols.clk = F::from_canonical_u32(event.clk);
                        cols.a_ptr = F::from_canonical_u32(event.a_ptr);
                        cols.b_ptr = F::from_canonical_u32(event.b_ptr);
                        cols.lo_ptr = F::from_canonical_u32(event.lo_ptr);
                        cols.hi_ptr = F::from_canonical_u32(event.hi_ptr);

                        // Populate memory accesses for lo_ptr and hi_ptr.
                        cols.lo_ptr_memory
                            .populate(event.lo_ptr_memory, &mut new_byte_lookup_events);
                        cols.hi_ptr_memory
                            .populate(event.hi_ptr_memory, &mut new_byte_lookup_events);

                        // Populate memory columns.
                        for i in 0..WORDS_FIELD_ELEMENT {
                            cols.a_memory[i]
                                .populate(event.a_memory_records[i], &mut new_byte_lookup_events);
                        }

                        for i in 0..WORDS_FIELD_ELEMENT * 8 {
                            cols.b_memory[i]
                                .populate(event.b_memory_records[i], &mut new_byte_lookup_events);
                        }

                        for i in 0..WORDS_FIELD_ELEMENT * 8 {
                            cols.lo_memory[i]
                                .populate(event.lo_memory_records[i], &mut new_byte_lookup_events);
                        }

                        for i in 0..WORDS_FIELD_ELEMENT {
                            cols.hi_memory[i]
                                .populate(event.hi_memory_records[i], &mut new_byte_lookup_events);
                        }

                        let a = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.a));
                        let b_array: [BigUint; 8] = event
                            .b
                            .chunks(8)
                            .map(|chunk| BigUint::from_bytes_le(&words_to_bytes_le::<32>(chunk)))
                            .collect::<Vec<_>>()
                            .try_into()
                            .unwrap();

                        let effective_modulus = BigUint::one() << 256;

                        let mut carries = vec![BigUint::zero(); 9];
                        let mut ab_plus_carry_cols = [
                            &mut cols.a_mul_b1,
                            &mut cols.ab2_plus_carry,
                            &mut cols.ab3_plus_carry,
                            &mut cols.ab4_plus_carry,
                            &mut cols.ab5_plus_carry,
                            &mut cols.ab6_plus_carry,
                            &mut cols.ab7_plus_carry,
                            &mut cols.ab8_plus_carry,
                        ];

                        for (i, col) in ab_plus_carry_cols.iter_mut().enumerate() {
                            let (_, carry) = col.populate_mul_and_carry(
                                &mut new_byte_lookup_events,
                                &a,
                                &b_array[i],
                                &carries[i],
                                &effective_modulus,
                            );
                            carries[i + 1] = carry;
                        }
                        row
                    })
                    .collect::<Vec<_>>();
                records.add_byte_lookup_events(new_byte_lookup_events);
                (rows, records)
            })
            .collect::<Vec<_>>();

        // Generate the trace rows for each event.
        let mut rows = Vec::new();
        for (row, mut record) in rows_and_records {
            rows.extend(row);
            output.append(&mut record);
        }

        pad_rows_fixed(
            &mut rows,
            || {
                let mut row: [F; NUM_COLS] = [F::zero(); NUM_COLS];
                let cols: &mut U256x2048MulCols<F> = row.as_mut_slice().borrow_mut();

                let x = BigUint::zero();
                let y = BigUint::zero();
                let z = BigUint::zero();
                let modulus = BigUint::one() << 256;

                // Populate all the mul and carry columns with zero values.
                cols.a_mul_b1.populate(&mut vec![], &x, &y, FieldOperation::Mul);
                cols.ab2_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
                cols.ab3_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
                cols.ab4_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
                cols.ab5_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
                cols.ab6_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
                cols.ab7_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
                cols.ab8_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);

                row
            },
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::U256XU2048_MUL).is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F> BaseAir<F> for U256x2048MulChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

impl<AB> Air<AB> for U256x2048MulChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &U256x2048MulCols<AB::Var> = (*local).borrow();

        // Assert that is_real is a boolean.
        builder.assert_bool(local.is_real);

        // Receive the arguments.
        builder.receive_syscall(
            local.shard,
            local.clk,
            AB::F::from_canonical_u32(SyscallCode::U256XU2048_MUL.syscall_id()),
            local.a_ptr,
            local.b_ptr,
            local.is_real,
            InteractionScope::Local,
        );

        // Evaluate that the lo_ptr and hi_ptr are read from the correct memory locations.
        builder.eval_memory_access(
            local.shard,
            local.clk.into(),
            AB::Expr::from_canonical_u32(LO_REGISTER),
            &local.lo_ptr_memory,
            local.is_real,
        );

        builder.eval_memory_access(
            local.shard,
            local.clk.into(),
            AB::Expr::from_canonical_u32(HI_REGISTER),
            &local.hi_ptr_memory,
            local.is_real,
        );

        // Evaluate the memory accesses for a_memory and b_memory.
        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into(),
            local.a_ptr,
            &local.a_memory,
            local.is_real,
        );

        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into(),
            local.b_ptr,
            &local.b_memory,
            local.is_real,
        );

        // Evaluate the memory accesses for lo_memory and hi_memory.
        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into() + AB::Expr::one(),
            local.lo_ptr,
            &local.lo_memory,
            local.is_real,
        );

        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into() + AB::Expr::one(),
            local.hi_ptr,
            &local.hi_memory,
            local.is_real,
        );

        let a_limbs =
            limbs_from_access::<AB::Var, <U256Field as NumLimbs>::Limbs, _>(&local.a_memory);

        // Iterate through chunks of 8 for b_memory and convert each chunk to its limbs.
        let b_limb_array = local
            .b_memory
            .chunks(8)
            .map(limbs_from_access::<AB::Var, <U256Field as NumLimbs>::Limbs, _>)
            .collect::<Vec<_>>();

        let mut coeff_2_256 = Vec::new();
        coeff_2_256.resize(32, AB::Expr::zero());
        coeff_2_256.push(AB::Expr::one());
        let modulus_polynomial: Polynomial<AB::Expr> = Polynomial::from_coefficients(&coeff_2_256);

        // Evaluate that each of the mul and carry columns are valid.
        let outputs = [
            &local.a_mul_b1,
            &local.ab2_plus_carry,
            &local.ab3_plus_carry,
            &local.ab4_plus_carry,
            &local.ab5_plus_carry,
            &local.ab6_plus_carry,
            &local.ab7_plus_carry,
            &local.ab8_plus_carry,
        ];

        outputs[0].eval_mul_and_carry(
            builder,
            &a_limbs,
            &b_limb_array[0],
            &Polynomial::from_coefficients(&[AB::Expr::zero()]), // Zero polynomial for no previous carry
            &modulus_polynomial,
            local.is_real,
        );

        for i in 1..outputs.len() {
            outputs[i].eval_mul_and_carry(
                builder,
                &a_limbs,
                &b_limb_array[i],
                &outputs[i - 1].carry,
                &modulus_polynomial,
                local.is_real,
            );
        }

        // Assert that the correct result is being written to hi_memory.
        builder
            .when(local.is_real)
            .assert_all_eq(outputs[outputs.len() - 1].carry, value_as_limbs(&local.hi_memory));

        // Loop through chunks of 8 for lo_memory and assert that each chunk is equal to corresponding result of outputs.
        for i in 0..8 {
            builder.when(local.is_real).assert_all_eq(
                outputs[i].result,
                value_as_limbs(
                    &local.lo_memory[i * WORDS_FIELD_ELEMENT..(i + 1) * WORDS_FIELD_ELEMENT],
                ),
            );
        }

        // Constrain that the lo_ptr is the value of lo_ptr_memory.
        builder
            .when(local.is_real)
            .assert_eq(local.lo_ptr, local.lo_ptr_memory.value().reduce::<AB>());

        // Constrain that the hi_ptr is the value of hi_ptr_memory.
        builder
            .when(local.is_real)
            .assert_eq(local.hi_ptr, local.hi_ptr_memory.value().reduce::<AB>());
    }
}
