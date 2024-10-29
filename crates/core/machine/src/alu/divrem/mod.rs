//! Division and remainder verification.
//!
//! This module implements the verification logic for division and remainder operations. It ensures
//! that for any given inputs b and c and outputs quotient and remainder, the equation
//!
//! b = c * quotient + remainder
//!
//! holds true, while also ensuring that the signs of `b` and `remainder` match.
//!
//! A critical aspect of this implementation is the use of 64-bit arithmetic for result calculation.
//! This choice is driven by the need to make the solution unique: in 32-bit arithmetic,
//! `c * quotient + remainder` could overflow, leading to results that are congruent modulo 2^{32}
//! and thus not uniquely defined. The 64-bit approach avoids this overflow, ensuring that each
//! valid input combination maps to a unique result.
//!
//! Implementation:
//!
//! # Use the multiplication ALU table. result is 64 bits.
//! result = quotient * c.
//!
//! # Add sign-extended remainder to result. Propagate carry to handle overflow within bytes.
//! base = pow(2, 8)
//! carry = 0
//! for i in range(8):
//!     x = result[i] + remainder[i] + carry
//!     result[i] = x % base
//!     carry = x // base
//!
//! # The number represented by c * quotient + remainder in 64 bits must equal b in 32 bits.
//!
//! # Assert the lower 32 bits of result match b.
//! assert result[0..4] == b[0..4]
//!
//! # Assert the upper 32 bits of result match the sign of b.
//! if (b == -2^{31}) and (c == -1):
//!     # This is the only exception as this is the only case where it overflows.
//!     assert result[4..8] == [0, 0, 0, 0]
//! elif b < 0:
//!     assert result[4..8] == [0xff, 0xff, 0xff, 0xff]
//! else:
//!     assert result[4..8] == [0, 0, 0, 0]
//!
//! # Check a = quotient or remainder.
//! assert a == (quotient if opcode == division else remainder)
//!
//! # remainder and b must have the same sign.
//! if remainder < 0:
//!     assert b <= 0
//! if remainder > 0:
//!     assert b >= 0
//!
//! # abs(remainder) < abs(c)
//! if c < 0:
//!    assert c < remainder <= 0
//! elif c > 0:
//!    assert 0 <= remainder < c
//!
//! if is_c_0:
//!    # if division by 0, then quotient = 0xffffffff per RISC-V spec. This needs special care since
//!    # b = 0 * quotient + b is satisfied by any quotient.
//!    assert quotient = 0xffffffff

use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    get_msb, get_quotient_and_remainder, is_signed_operation, ByteOpcode, ExecutionRecord, Opcode,
    Program,
};
use sp1_derive::AlignedBorrow;
use sp1_primitives::consts::WORD_SIZE;
use sp1_stark::{air::MachineAir, Word};

use crate::{
    air::SP1CoreAirBuilder,
    operations::{IsEqualWordOperation, IsZeroWordOperation},
    utils::pad_rows_fixed,
};

/// The number of main trace columns for `DivRemChip`.
pub const NUM_DIVREM_COLS: usize = size_of::<DivRemCols<u8>>();

/// The size of a byte in bits.
const BYTE_SIZE: usize = 8;

/// The size of a 64-bit in bytes.
const LONG_WORD_SIZE: usize = 2 * WORD_SIZE;

/// A chip that implements addition for the opcodes DIV/REM.
#[derive(Default)]
pub struct DivRemChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct DivRemCols<T> {
    /// The shard number, used for byte lookup table.
    pub shard: T,

    /// The nonce of the operation.
    pub nonce: T,

    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Results of dividing `b` by `c`.
    pub quotient: Word<T>,

    /// Remainder when dividing `b` by `c`.
    pub remainder: Word<T>,

    /// `abs(remainder)`, used to check `abs(remainder) < abs(c)`.
    pub abs_remainder: Word<T>,

    /// `abs(c)`, used to check `abs(remainder) < abs(c)`.
    pub abs_c: Word<T>,

    /// `max(abs(c), 1)`, used to check `abs(remainder) < abs(c)`.
    pub max_abs_c_or_1: Word<T>,

    /// The result of `c * quotient`.
    pub c_times_quotient: [T; LONG_WORD_SIZE],

    /// Carry propagated when adding `remainder` by `c * quotient`.
    pub carry: [T; LONG_WORD_SIZE],

    /// Flag to indicate division by 0.
    pub is_c_0: IsZeroWordOperation<T>,

    /// Flag to indicate whether the opcode is DIV.
    pub is_div: T,

    /// Flag to indicate whether the opcode is DIVU.
    pub is_divu: T,

    /// Flag to indicate whether the opcode is REM.
    pub is_rem: T,

    /// Flag to indicate whether the opcode is REMU.
    pub is_remu: T,

    /// Flag to indicate whether the division operation overflows.
    ///
    /// Overflow occurs in a specific case of signed 32-bit integer division: when `b` is the
    /// minimum representable value (`-2^31`, the smallest negative number) and `c` is `-1`. In
    /// this case, the division result exceeds the maximum positive value representable by a
    /// 32-bit signed integer.
    pub is_overflow: T,

    /// Flag for whether the value of `b` matches the unique overflow case `b = -2^31` and `c =
    /// -1`.
    pub is_overflow_b: IsEqualWordOperation<T>,

    /// Flag for whether the value of `c` matches the unique overflow case `b = -2^31` and `c =
    /// -1`.
    pub is_overflow_c: IsEqualWordOperation<T>,

    /// The most significant bit of `b`.
    pub b_msb: T,

    /// The most significant bit of remainder.
    pub rem_msb: T,

    /// The most significant bit of `c`.
    pub c_msb: T,

    /// Flag to indicate whether `b` is negative.
    pub b_neg: T,

    /// Flag to indicate whether `rem_neg` is negative.
    pub rem_neg: T,

    /// Flag to indicate whether `c` is negative.
    pub c_neg: T,

    /// The lower nonce of the operation.
    pub lower_nonce: T,

    /// The upper nonce of the operation.
    pub upper_nonce: T,

    /// The absolute nonce of the operation.
    pub abs_nonce: T,

    /// Selector to determine whether an ALU Event is sent for absolute value computation of `c`.
    pub abs_c_alu_event: T,
    pub abs_c_alu_event_nonce: T,

    /// Selector to determine whether an ALU Event is sent for absolute value computation of `rem`.
    pub abs_rem_alu_event: T,
    pub abs_rem_alu_event_nonce: T,

    /// Selector to know whether this row is enabled.
    pub is_real: T,

    /// Column to modify multiplicity for remainder range check event.
    pub remainder_check_multiplicity: T,
}

impl<F: PrimeField> MachineAir<F> for DivRemChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "DivRem".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let mut rows: Vec<[F; NUM_DIVREM_COLS]> = vec![];
        let divrem_events = input.divrem_events.clone();
        for event in divrem_events.iter() {
            assert!(
                event.opcode == Opcode::DIVU
                    || event.opcode == Opcode::REMU
                    || event.opcode == Opcode::REM
                    || event.opcode == Opcode::DIV
            );
            let mut row = [F::zero(); NUM_DIVREM_COLS];
            let cols: &mut DivRemCols<F> = row.as_mut_slice().borrow_mut();

            // Initialize cols with basic operands and flags derived from the current event.
            {
                cols.a = Word::from(event.a);
                cols.b = Word::from(event.b);
                cols.c = Word::from(event.c);
                cols.shard = F::from_canonical_u32(event.shard);
                cols.is_real = F::one();
                cols.is_divu = F::from_bool(event.opcode == Opcode::DIVU);
                cols.is_remu = F::from_bool(event.opcode == Opcode::REMU);
                cols.is_div = F::from_bool(event.opcode == Opcode::DIV);
                cols.is_rem = F::from_bool(event.opcode == Opcode::REM);
                cols.is_c_0.populate(event.c);
            }

            let (quotient, remainder) = get_quotient_and_remainder(event.b, event.c, event.opcode);
            cols.quotient = Word::from(quotient);
            cols.remainder = Word::from(remainder);

            // Calculate flags for sign detection.
            {
                cols.rem_msb = F::from_canonical_u8(get_msb(remainder));
                cols.b_msb = F::from_canonical_u8(get_msb(event.b));
                cols.c_msb = F::from_canonical_u8(get_msb(event.c));
                cols.is_overflow_b.populate(event.b, i32::MIN as u32);
                cols.is_overflow_c.populate(event.c, -1i32 as u32);
                if is_signed_operation(event.opcode) {
                    cols.rem_neg = cols.rem_msb;
                    cols.b_neg = cols.b_msb;
                    cols.c_neg = cols.c_msb;
                    cols.is_overflow =
                        F::from_bool(event.b as i32 == i32::MIN && event.c as i32 == -1);
                    cols.abs_remainder = Word::from((remainder as i32).abs() as u32);
                    cols.abs_c = Word::from((event.c as i32).abs() as u32);
                    cols.max_abs_c_or_1 = Word::from(u32::max(1, (event.c as i32).abs() as u32));
                } else {
                    cols.abs_remainder = cols.remainder;
                    cols.abs_c = cols.c;
                    cols.max_abs_c_or_1 = Word::from(u32::max(1, event.c));
                }

                // Set the `alu_event` flags.
                cols.abs_c_alu_event = cols.c_neg * cols.is_real;
                cols.abs_c_alu_event_nonce = F::from_canonical_u32(
                    input.nonce_lookup.get(&event.sub_lookups[4]).copied().unwrap_or_default(),
                );
                cols.abs_rem_alu_event = cols.rem_neg * cols.is_real;
                cols.abs_rem_alu_event_nonce = F::from_canonical_u32(
                    input.nonce_lookup.get(&event.sub_lookups[5]).copied().unwrap_or_default(),
                );

                // Insert the MSB lookup events.
                {
                    let words = [event.b, event.c, remainder];
                    let mut blu_events: Vec<ByteLookupEvent> = vec![];
                    for word in words.iter() {
                        let most_significant_byte = word.to_le_bytes()[WORD_SIZE - 1];
                        blu_events.push(ByteLookupEvent {
                            shard: event.shard,
                            opcode: ByteOpcode::MSB,
                            a1: get_msb(*word) as u16,
                            a2: 0,
                            b: most_significant_byte,
                            c: 0,
                        });
                    }
                    output.add_byte_lookup_events(blu_events);
                }
            }

            // Calculate the modified multiplicity
            {
                cols.remainder_check_multiplicity = cols.is_real * (F::one() - cols.is_c_0.result);
            }

            // Calculate c * quotient + remainder.
            {
                let c_times_quotient = {
                    if is_signed_operation(event.opcode) {
                        (((quotient as i32) as i64) * ((event.c as i32) as i64)).to_le_bytes()
                    } else {
                        ((quotient as u64) * (event.c as u64)).to_le_bytes()
                    }
                };
                cols.c_times_quotient = c_times_quotient.map(F::from_canonical_u8);

                let remainder_bytes = {
                    if is_signed_operation(event.opcode) {
                        ((remainder as i32) as i64).to_le_bytes()
                    } else {
                        (remainder as u64).to_le_bytes()
                    }
                };

                // Add remainder to product.
                let mut carry = [0u32; 8];
                let base = 1 << BYTE_SIZE;
                for i in 0..LONG_WORD_SIZE {
                    let mut x = c_times_quotient[i] as u32 + remainder_bytes[i] as u32;
                    if i > 0 {
                        x += carry[i - 1];
                    }
                    carry[i] = x / base;
                    cols.carry[i] = F::from_canonical_u32(carry[i]);
                }

                // Insert the necessary multiplication & LT events.
                {
                    cols.lower_nonce = F::from_canonical_u32(
                        input.nonce_lookup.get(&event.sub_lookups[0]).copied().unwrap_or_default(),
                    );
                    cols.upper_nonce = F::from_canonical_u32(
                        input.nonce_lookup.get(&event.sub_lookups[1]).copied().unwrap_or_default(),
                    );
                    if is_signed_operation(event.opcode) {
                        cols.abs_nonce = F::from_canonical_u32(
                            input
                                .nonce_lookup
                                .get(&event.sub_lookups[2])
                                .copied()
                                .unwrap_or_default(),
                        );
                    } else {
                        cols.abs_nonce = F::from_canonical_u32(
                            input
                                .nonce_lookup
                                .get(&event.sub_lookups[3])
                                .copied()
                                .unwrap_or_default(),
                        );
                    };
                }

                // Range check.
                {
                    output.add_u8_range_checks(event.shard, &quotient.to_le_bytes());
                    output.add_u8_range_checks(event.shard, &remainder.to_le_bytes());
                    output.add_u8_range_checks(event.shard, &c_times_quotient);
                }
            }

            rows.push(row);
        }

        // Pad the trace to a power of two depending on the proof shape in `input`.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_DIVREM_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_DIVREM_COLS);

        // Create the template for the padded rows. These are fake rows that don't fail on some
        // sanity checks.
        let padded_row_template = {
            let mut row = [F::zero(); NUM_DIVREM_COLS];
            let cols: &mut DivRemCols<F> = row.as_mut_slice().borrow_mut();
            // 0 divided by 1. quotient = remainder = 0.
            cols.is_divu = F::one();
            cols.c[0] = F::one();
            cols.abs_c[0] = F::one();
            cols.max_abs_c_or_1[0] = F::one();

            cols.is_c_0.populate(1);

            row
        };
        debug_assert!(padded_row_template.len() == NUM_DIVREM_COLS);
        for i in input.divrem_events.len() * NUM_DIVREM_COLS..trace.values.len() {
            trace.values[i] = padded_row_template[i % NUM_DIVREM_COLS];
        }

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut DivRemCols<F> =
                trace.values[i * NUM_DIVREM_COLS..(i + 1) * NUM_DIVREM_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.divrem_events.is_empty()
        }
    }
}

impl<F> BaseAir<F> for DivRemChip {
    fn width(&self) -> usize {
        NUM_DIVREM_COLS
    }
}

impl<AB> Air<AB> for DivRemChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &DivRemCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &DivRemCols<AB::Var> = (*next).borrow();
        let base = AB::F::from_canonical_u32(1 << 8);
        let one: AB::Expr = AB::F::one().into();
        let zero: AB::Expr = AB::F::zero().into();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        // Calculate whether b, remainder, and c are negative.
        {
            // Negative if and only if op code is signed & MSB = 1.
            let is_signed_type = local.is_div + local.is_rem;
            let msb_sign_pairs = [
                (local.b_msb, local.b_neg),
                (local.rem_msb, local.rem_neg),
                (local.c_msb, local.c_neg),
            ];

            for msb_sign_pair in msb_sign_pairs.iter() {
                let msb = msb_sign_pair.0;
                let is_negative = msb_sign_pair.1;
                builder.assert_eq(msb * is_signed_type.clone(), is_negative);
            }
        }

        // Use the mul table to compute c * quotient and compare it to local.c_times_quotient.
        {
            let lower_half: [AB::Expr; 4] = [
                local.c_times_quotient[0].into(),
                local.c_times_quotient[1].into(),
                local.c_times_quotient[2].into(),
                local.c_times_quotient[3].into(),
            ];

            // The lower 4 bytes of c_times_quotient must match the lower 4 bytes of (c * quotient).
            builder.send_alu(
                AB::Expr::from_canonical_u32(Opcode::MUL as u32),
                Word(lower_half),
                local.quotient,
                local.c,
                local.shard,
                local.lower_nonce,
                local.is_real,
            );

            let opcode_for_upper_half = {
                let mulh = AB::Expr::from_canonical_u32(Opcode::MULH as u32);
                let mulhu = AB::Expr::from_canonical_u32(Opcode::MULHU as u32);
                let is_signed = local.is_div + local.is_rem;
                let is_unsigned = local.is_divu + local.is_remu;
                is_signed * mulh + is_unsigned * mulhu
            };

            let upper_half: [AB::Expr; 4] = [
                local.c_times_quotient[4].into(),
                local.c_times_quotient[5].into(),
                local.c_times_quotient[6].into(),
                local.c_times_quotient[7].into(),
            ];

            builder.send_alu(
                opcode_for_upper_half,
                Word(upper_half),
                local.quotient,
                local.c,
                local.shard,
                local.upper_nonce,
                local.is_real,
            );
        }

        // Calculate is_overflow. is_overflow = is_equal(b, -2^{31}) * is_equal(c, -1) * is_signed
        {
            IsEqualWordOperation::<AB::F>::eval(
                builder,
                local.b.map(|x| x.into()),
                Word::from(i32::MIN as u32).map(|x: AB::F| x.into()),
                local.is_overflow_b,
                local.is_real.into(),
            );

            IsEqualWordOperation::<AB::F>::eval(
                builder,
                local.c.map(|x| x.into()),
                Word::from(-1i32 as u32).map(|x: AB::F| x.into()),
                local.is_overflow_c,
                local.is_real.into(),
            );

            let is_signed = local.is_div + local.is_rem;

            builder.assert_eq(
                local.is_overflow,
                local.is_overflow_b.is_diff_zero.result
                    * local.is_overflow_c.is_diff_zero.result
                    * is_signed,
            );
        }

        // Add remainder to product c * quotient, and compare it to b.
        {
            let sign_extension = local.rem_neg * AB::F::from_canonical_u8(u8::MAX);
            let mut c_times_quotient_plus_remainder: Vec<AB::Expr> =
                vec![AB::F::zero().into(); LONG_WORD_SIZE];

            // Add remainder to c_times_quotient and propagate carry.
            for i in 0..LONG_WORD_SIZE {
                c_times_quotient_plus_remainder[i] = local.c_times_quotient[i].into();

                // Add remainder.
                if i < WORD_SIZE {
                    c_times_quotient_plus_remainder[i] += local.remainder[i].into();
                } else {
                    // If rem is negative, add 0xff to the upper 4 bytes.
                    c_times_quotient_plus_remainder[i] += sign_extension.clone();
                }

                // Propagate carry.
                c_times_quotient_plus_remainder[i] -= local.carry[i] * base;
                if i > 0 {
                    c_times_quotient_plus_remainder[i] += local.carry[i - 1].into();
                }
            }

            // Compare c_times_quotient_plus_remainder to b by checking each limb.
            for i in 0..LONG_WORD_SIZE {
                if i < WORD_SIZE {
                    // The lower 4 bytes of the result must match the corresponding bytes in b.
                    builder.assert_eq(local.b[i], c_times_quotient_plus_remainder[i].clone());
                } else {
                    // The upper 4 bytes must reflect the sign of b in two's complement:
                    // - All 1s (0xff) for negative b.
                    // - All 0s for non-negative b.
                    let not_overflow = one.clone() - local.is_overflow;
                    builder.when(not_overflow.clone()).when(local.b_neg).assert_eq(
                        c_times_quotient_plus_remainder[i].clone(),
                        AB::F::from_canonical_u8(u8::MAX),
                    );
                    builder
                        .when(not_overflow.clone())
                        .when_ne(one.clone(), local.b_neg)
                        .assert_zero(c_times_quotient_plus_remainder[i].clone());

                    // The only exception to the upper-4-byte check is the overflow case.
                    builder
                        .when(local.is_overflow)
                        .assert_zero(c_times_quotient_plus_remainder[i].clone());
                }
            }
        }

        // a must equal remainder or quotient depending on the opcode.
        for i in 0..WORD_SIZE {
            builder.when(local.is_divu + local.is_div).assert_eq(local.quotient[i], local.a[i]);
            builder.when(local.is_remu + local.is_rem).assert_eq(local.remainder[i], local.a[i]);
        }

        // remainder and b must have the same sign. Due to the intricate nature of sign logic in ZK,
        // we will check a slightly stronger condition:
        //
        // 1. If remainder < 0, then b < 0.
        // 2. If remainder > 0, then b >= 0.
        {
            // A number is 0 if and only if the sum of the 4 limbs equals to 0.
            let mut rem_byte_sum = zero.clone();
            let mut b_byte_sum = zero.clone();
            for i in 0..WORD_SIZE {
                rem_byte_sum += local.remainder[i].into();
                b_byte_sum += local.b[i].into();
            }

            // 1. If remainder < 0, then b < 0.
            builder
                .when(local.rem_neg) // rem is negative.
                .assert_one(local.b_neg); // b is negative.

            // 2. If remainder > 0, then b >= 0.
            builder
                .when(rem_byte_sum.clone()) // remainder is nonzero.
                .when(one.clone() - local.rem_neg) // rem is not negative.
                .assert_zero(local.b_neg); // b is not negative.
        }

        // When division by 0, quotient must be 0xffffffff per RISC-V spec.
        {
            // Calculate whether c is 0.
            IsZeroWordOperation::<AB::F>::eval(
                builder,
                local.c.map(|x| x.into()),
                local.is_c_0,
                local.is_real.into(),
            );

            // If is_c_0 is true, then quotient must be 0xffffffff = u32::MAX.
            for i in 0..WORD_SIZE {
                builder
                    .when(local.is_c_0.result)
                    .when(local.is_divu + local.is_div)
                    .assert_eq(local.quotient[i], AB::F::from_canonical_u8(u8::MAX));
            }
        }

        // Range check remainder. (i.e., |remainder| < |c| when not is_c_0)
        {
            // For each of `c` and `rem`, assert that the absolute value is equal to the original
            // value, if the original value is non-negative or the minimum i32.
            for i in 0..WORD_SIZE {
                builder.when_not(local.c_neg).assert_eq(local.c[i], local.abs_c[i]);
                builder
                    .when_not(local.rem_neg)
                    .assert_eq(local.remainder[i], local.abs_remainder[i]);
            }
            // In the case that `c` or `rem` is negative, instead check that their sum is zero by
            // sending an AddEvent.
            builder.send_alu(
                AB::Expr::from_canonical_u32(Opcode::ADD as u32),
                Word([zero.clone(), zero.clone(), zero.clone(), zero.clone()]),
                local.c,
                local.abs_c,
                local.shard,
                local.abs_c_alu_event_nonce,
                local.abs_c_alu_event,
            );
            builder.send_alu(
                AB::Expr::from_canonical_u32(Opcode::ADD as u32),
                Word([zero.clone(), zero.clone(), zero.clone(), zero.clone()]),
                local.remainder,
                local.abs_remainder,
                local.shard,
                local.abs_rem_alu_event_nonce,
                local.abs_rem_alu_event,
            );

            // max(abs(c), 1) = abs(c) * (1 - is_c_0) + 1 * is_c_0
            let max_abs_c_or_1: Word<AB::Expr> = {
                let mut v = vec![zero.clone(); WORD_SIZE];

                // Set the least significant byte to 1 if is_c_0 is true.
                v[0] = local.is_c_0.result * one.clone()
                    + (one.clone() - local.is_c_0.result) * local.abs_c[0];

                // Set the remaining bytes to 0 if is_c_0 is true.
                for i in 1..WORD_SIZE {
                    v[i] = (one.clone() - local.is_c_0.result) * local.abs_c[i];
                }
                Word(v.try_into().unwrap_or_else(|_| panic!("Incorrect length")))
            };
            for i in 0..WORD_SIZE {
                builder.assert_eq(local.max_abs_c_or_1[i], max_abs_c_or_1[i].clone());
            }

            // Handle cases:
            // - If is_real == 0 then remainder_check_multiplicity == 0 is forced.
            // - If is_real == 1 then is_c_0_result must be the expected one, so
            //   remainder_check_multiplicity = (1 - is_c_0_result) * is_real.
            builder.assert_eq(
                (AB::Expr::one() - local.is_c_0.result) * local.is_real,
                local.remainder_check_multiplicity,
            );

            // the cleaner idea is simply remainder_check_multiplicity == (1 - is_c_0_result) *
            // is_real

            // Check that the absolute value selector columns are computed correctly.
            builder.assert_eq(local.abs_c_alu_event, local.c_neg * local.is_real);
            builder.assert_eq(local.abs_rem_alu_event, local.rem_neg * local.is_real);

            // Dispatch abs(remainder) < max(abs(c), 1), this is equivalent to abs(remainder) <
            // abs(c) if not division by 0.
            builder.send_alu(
                AB::Expr::from_canonical_u32(Opcode::SLTU as u32),
                Word([one.clone(), zero.clone(), zero.clone(), zero.clone()]),
                local.abs_remainder,
                local.max_abs_c_or_1,
                local.shard,
                local.abs_nonce,
                local.remainder_check_multiplicity,
            );
        }

        // Check that the MSBs are correct.
        {
            let msb_pairs = [
                (local.b_msb, local.b[WORD_SIZE - 1]),
                (local.c_msb, local.c[WORD_SIZE - 1]),
                (local.rem_msb, local.remainder[WORD_SIZE - 1]),
            ];
            let opcode = AB::F::from_canonical_u32(ByteOpcode::MSB as u32);
            for msb_pair in msb_pairs.iter() {
                let msb = msb_pair.0;
                let byte = msb_pair.1;
                builder.send_byte(opcode, msb, byte, zero.clone(), local.is_real);
            }
        }

        // Range check all the bytes.
        {
            builder.slice_range_check_u8(&local.quotient.0, local.is_real);
            builder.slice_range_check_u8(&local.remainder.0, local.is_real);

            local.carry.iter().for_each(|carry| {
                builder.assert_bool(*carry);
            });

            builder.slice_range_check_u8(&local.c_times_quotient, local.is_real);
        }

        // Check that the flags are boolean.
        {
            let bool_flags = [
                local.is_div,
                local.is_divu,
                local.is_rem,
                local.is_remu,
                local.is_overflow,
                local.b_msb,
                local.rem_msb,
                local.c_msb,
                local.b_neg,
                local.rem_neg,
                local.c_neg,
                local.is_real,
                local.abs_c_alu_event,
                local.abs_rem_alu_event,
            ];

            for flag in bool_flags.iter() {
                builder.assert_bool(*flag);
            }
        }

        // Receive the arguments.
        {
            // Exactly one of the opcode flags must be on.
            builder.assert_eq(
                one.clone(),
                local.is_divu + local.is_remu + local.is_div + local.is_rem,
            );

            let opcode = {
                let divu: AB::Expr = AB::F::from_canonical_u32(Opcode::DIVU as u32).into();
                let remu: AB::Expr = AB::F::from_canonical_u32(Opcode::REMU as u32).into();
                let div: AB::Expr = AB::F::from_canonical_u32(Opcode::DIV as u32).into();
                let rem: AB::Expr = AB::F::from_canonical_u32(Opcode::REM as u32).into();

                local.is_divu * divu
                    + local.is_remu * remu
                    + local.is_div * div
                    + local.is_rem * rem
            };

            builder.receive_alu(
                opcode,
                local.a,
                local.b,
                local.c,
                local.shard,
                local.nonce,
                local.is_real,
            );
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::utils::{uni_stark_prove, uni_stark_verify};
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use sp1_core_executor::{events::AluEvent, ExecutionRecord, Opcode};
    use sp1_stark::{air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig};

    use super::DivRemChip;

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.divrem_events = vec![AluEvent::new(0, 0, Opcode::DIVU, 2, 17, 3)];
        let chip = DivRemChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    fn neg(a: u32) -> u32 {
        u32::MAX - a + 1
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut divrem_events: Vec<AluEvent> = Vec::new();

        let divrems: Vec<(Opcode, u32, u32, u32)> = vec![
            (Opcode::DIVU, 3, 20, 6),
            (Opcode::DIVU, 715827879, neg(20), 6),
            (Opcode::DIVU, 0, 20, neg(6)),
            (Opcode::DIVU, 0, neg(20), neg(6)),
            (Opcode::DIVU, 1 << 31, 1 << 31, 1),
            (Opcode::DIVU, 0, 1 << 31, neg(1)),
            (Opcode::DIVU, u32::MAX, 1 << 31, 0),
            (Opcode::DIVU, u32::MAX, 1, 0),
            (Opcode::DIVU, u32::MAX, 0, 0),
            (Opcode::REMU, 4, 18, 7),
            (Opcode::REMU, 6, neg(20), 11),
            (Opcode::REMU, 23, 23, neg(6)),
            (Opcode::REMU, neg(21), neg(21), neg(11)),
            (Opcode::REMU, 5, 5, 0),
            (Opcode::REMU, neg(1), neg(1), 0),
            (Opcode::REMU, 0, 0, 0),
            (Opcode::REM, 7, 16, 9),
            (Opcode::REM, neg(4), neg(22), 6),
            (Opcode::REM, 1, 25, neg(3)),
            (Opcode::REM, neg(2), neg(22), neg(4)),
            (Opcode::REM, 0, 873, 1),
            (Opcode::REM, 0, 873, neg(1)),
            (Opcode::REM, 5, 5, 0),
            (Opcode::REM, neg(5), neg(5), 0),
            (Opcode::REM, 0, 0, 0),
            (Opcode::REM, 0, 0x80000001, neg(1)),
            (Opcode::DIV, 3, 18, 6),
            (Opcode::DIV, neg(6), neg(24), 4),
            (Opcode::DIV, neg(2), 16, neg(8)),
            (Opcode::DIV, neg(1), 0, 0),
            (Opcode::DIV, 1 << 31, 1 << 31, neg(1)),
            (Opcode::REM, 0, 1 << 31, neg(1)),
        ];
        for t in divrems.iter() {
            divrem_events.push(AluEvent::new(0, 0, t.0, t.1, t.2, t.3));
        }

        // Append more events until we have 1000 tests.
        for _ in 0..(1000 - divrems.len()) {
            divrem_events.push(AluEvent::new(0, 0, Opcode::DIVU, 1, 1, 1));
        }

        let mut shard = ExecutionRecord::default();
        shard.divrem_events = divrem_events;
        let chip = DivRemChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = uni_stark_prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        uni_stark_verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
