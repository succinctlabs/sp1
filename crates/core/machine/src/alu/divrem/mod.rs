use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};
use std::{marker::PhantomData, num::Wrapping};

use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    get_msb, get_quotient_and_remainder, is_signed_64bit_operation, is_signed_word_operation,
    is_unsigned_64bit_operation, is_unsigned_word_operation, is_word_operation, ExecutionRecord,
    Opcode, Program, CLK_INC, PC_INC,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{air::MachineAir, Word};
use sp1_primitives::consts::WORD_SIZE;
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::{
    adapter::{
        register::r_type::{RTypeReader, RTypeReaderInput},
        state::{CPUState, CPUStateInput},
    },
    air::{SP1CoreAirBuilder, SP1Operation, WordAirBuilder},
    eval_untrusted_program,
    operations::{
        AddOperation, AddOperationInput, IsEqualWordOperation, IsEqualWordOperationInput,
        IsZeroWordOperation, IsZeroWordOperationInput, LtOperationUnsigned,
        LtOperationUnsignedInput, MulOperation, MulOperationInput, U16MSBOperation,
        U16MSBOperationInput,
    },
    utils::next_multiple_of_32,
    SupervisorMode, TrustMode, UserMode,
};

/// The number of main trace columns for `DivRemChip` in supervisor mode.
pub const NUM_DIVREM_COLS_SUPERVISOR: usize = size_of::<DivRemCols<u8, SupervisorMode>>();

/// The number of main trace columns for `DivRemChip` in user mode.
pub const NUM_DIVREM_COLS_USER: usize = size_of::<DivRemCols<u8, UserMode>>();

/// The size of a 128-bit in limbs.
const LONG_WORD_SIZE: usize = 2 * WORD_SIZE;

/// A chip that implements division for the opcodes DIV/REM.
#[derive(Default)]
pub struct DivRemChip<M: TrustMode> {
    pub _phantom: PhantomData<M>,
}

/// The column layout for the chip.
#[derive(AlignedBorrow, StructReflection, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct DivRemCols<T, M: TrustMode> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: RTypeReader<T>,

    /// The output operand.
    pub a: Word<T>,

    /// The input operand (b sign extended if word operation).
    pub b: Word<T>,

    /// The input operand (c sign extended if word operation).
    pub c: Word<T>,

    /// Results of dividing `b` by `c`.
    pub quotient: Word<T>,

    /// The quotient used in the computation of `c * quotient + remainder`
    /// (truncated in the case of unsigned word operation).
    pub quotient_comp: Word<T>,

    /// The remainder used in the computation of `c * quotient + remainder`
    /// (truncated in the case of unsigned word operation).
    pub remainder_comp: Word<T>,

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

    /// Instance of `MulOperation` for the lower half of `c * quotient`.
    pub c_times_quotient_lower: MulOperation<T>,

    /// Instance of `MulOperation` for the upper half of `c * quotient`.
    pub c_times_quotient_upper: MulOperation<T>,

    /// Instance of `AddOperation` to get the negative of `c`
    pub c_neg_operation: AddOperation<T>,

    /// Instance of `AddOperation` to get the negative of `remainder`.
    pub rem_neg_operation: AddOperation<T>,

    /// Instance of `LtOperation` to check if abs(remainder) < abs(c).
    pub remainder_lt_operation: LtOperationUnsigned<T>,

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

    /// Flag to indicate whether the opcode is DIVW.
    pub is_divw: T,

    /// Flag to indicate whether the opcode is REMW.
    pub is_remw: T,

    /// Flag to indicate whether the opcode is DIVUW.
    pub is_divuw: T,

    /// Flag to indicate whether the opcode is REMUW.
    pub is_remuw: T,

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
    pub b_msb: U16MSBOperation<T>,

    /// The most significant bit of remainder.
    pub rem_msb: U16MSBOperation<T>,

    /// The most significant bit of `c`.
    pub c_msb: U16MSBOperation<T>,

    /// The most significant bit of `quotient`.
    pub quot_msb: U16MSBOperation<T>,

    /// Flag to indicate whether `b` is negative.
    pub b_neg: T,

    /// Flag to indicate whether `b` is negative and not is_overflow.
    pub b_neg_not_overflow: T,

    /// Flag to indicate whether `b` is not negative and not is_overflow.
    pub b_not_neg_not_overflow: T,

    /// Flag to indicate whether is_real and not word operation.
    pub is_real_not_word: T,

    /// Flag to indicate whether `rem_neg` is negative.
    pub rem_neg: T,

    /// Flag to indicate whether `c` is negative.
    pub c_neg: T,

    /// Selector to determine whether an ALU Event is sent for absolute value computation of `c`.
    pub abs_c_alu_event: T,

    /// Selector to determine whether an ALU Event is sent for absolute value computation of `rem`.
    pub abs_rem_alu_event: T,

    /// Selector to know whether this row is enabled.
    pub is_real: T,

    /// Column to modify multiplicity for remainder range check event.
    pub remainder_check_multiplicity: T,

    /// Adapter columns for trust mode specific data.
    pub adapter_cols: M::AdapterCols<T>,
}

impl<F: PrimeField32, M: TrustMode> MachineAir<F> for DivRemChip<M> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            "DivRem"
        } else {
            "DivRemUser"
        }
    }

    fn column_names(&self) -> Vec<String> {
        DivRemCols::<F, M>::struct_reflection().unwrap()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows =
            next_multiple_of_32(input.divrem_events.len(), input.fixed_log2_rows::<F, _>(self));
        Some(nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }
        // Generate the trace rows for each event.
        let padded_nb_rows = <DivRemChip<M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let width = <DivRemChip<M> as BaseAir<F>>::width(self);

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * width) };

        let divrem_events = input.divrem_events.clone();
        for (row_idx, event_record) in divrem_events.iter().enumerate() {
            let event = event_record.0;
            let r_record = event_record.1;

            assert!(
                event.opcode == Opcode::DIVU
                    || event.opcode == Opcode::REMU
                    || event.opcode == Opcode::REM
                    || event.opcode == Opcode::DIV
                    || event.opcode == Opcode::DIVW
                    || event.opcode == Opcode::REMW
                    || event.opcode == Opcode::DIVUW
                    || event.opcode == Opcode::REMUW
            );

            let row_start = row_idx * width;
            let row = &mut values[row_start..row_start + width];

            // Zero-initialize the row here.
            unsafe {
                core::ptr::write_bytes(row.as_mut_ptr(), 0, width);
            }

            let cols: &mut DivRemCols<F, M> = row.borrow_mut();

            {
                let mut blu = vec![];
                cols.state.populate(&mut blu, event.clk, event.pc);
                cols.adapter.populate(&mut blu, r_record);
                output.add_byte_lookup_events(blu);
            }

            // Get the correct computational values of `b`.
            let b = if is_signed_word_operation(event.opcode) {
                event.b as i32 as i64 as u64
            } else if is_unsigned_word_operation(event.opcode) {
                event.b as u32 as u64
            } else {
                event.b
            };

            // Get the correct computational values of `c`.
            let c = if is_signed_word_operation(event.opcode) {
                event.c as i32 as i64 as u64
            } else if is_unsigned_word_operation(event.opcode) {
                event.c as u32 as u64
            } else {
                event.c
            };

            // Initialize cols with basic operands and flags derived from the current event.
            {
                cols.a = Word::from(event.a);
                cols.b = Word::from(b);
                cols.c = Word::from(c);

                cols.is_real = F::one();

                cols.is_divu = F::from_bool(event.opcode == Opcode::DIVU);
                cols.is_remu = F::from_bool(event.opcode == Opcode::REMU);
                cols.is_div = F::from_bool(event.opcode == Opcode::DIV);
                cols.is_rem = F::from_bool(event.opcode == Opcode::REM);
                cols.is_divw = F::from_bool(event.opcode == Opcode::DIVW);
                cols.is_divuw = F::from_bool(event.opcode == Opcode::DIVUW);
                cols.is_remw = F::from_bool(event.opcode == Opcode::REMW);
                cols.is_remuw = F::from_bool(event.opcode == Opcode::REMUW);

                let not_word_operation =
                    F::one() - cols.is_divw - cols.is_remw - cols.is_divuw - cols.is_remuw;
                cols.is_real_not_word = cols.is_real * not_word_operation;
                cols.is_c_0.populate(c);
            }

            let (quotient, remainder) = get_quotient_and_remainder(event.b, event.c, event.opcode);
            cols.quotient = Word::from(quotient);
            cols.remainder = Word::from(remainder);

            // Get the computational form of `quotient`.
            let quotient_comp = if is_unsigned_word_operation(event.opcode) {
                quotient as u32 as u64
            } else {
                quotient
            };
            cols.quotient_comp = Word::from(quotient_comp);

            // Get the computational form of `remainder`.
            let remainder_comp = if is_unsigned_word_operation(event.opcode) {
                remainder as u32 as u64
            } else {
                remainder
            };
            cols.remainder_comp = Word::from(remainder_comp);

            // Calculate flags for sign detection.
            {
                if is_signed_64bit_operation(event.opcode) {
                    cols.rem_neg = F::from_canonical_u8(get_msb(remainder));
                    cols.b_neg = F::from_canonical_u8(get_msb(event.b));
                    cols.c_neg = F::from_canonical_u8(get_msb(event.c));
                    cols.is_overflow =
                        F::from_bool(event.b as i64 == i64::MIN && event.c as i64 == -1);
                    cols.abs_remainder = Word::from((remainder as i64).unsigned_abs());
                    cols.abs_c = Word::from((event.c as i64).unsigned_abs());
                    cols.max_abs_c_or_1 = Word::from(u64::max(1, (event.c as i64).unsigned_abs()));
                } else if is_signed_word_operation(event.opcode) {
                    cols.rem_neg = F::from_canonical_u8(get_msb((remainder as i32) as i64 as u64));
                    cols.b_neg = F::from_canonical_u8(get_msb((event.b as i32) as i64 as u64));
                    cols.c_neg = F::from_canonical_u8(get_msb((event.c as i32) as i64 as u64));
                    cols.is_overflow =
                        F::from_bool(event.b as i32 == i32::MIN && event.c as i32 == -1);
                    cols.abs_remainder = Word::from((remainder as i64).unsigned_abs());
                    cols.abs_c = Word::from((c as i64).unsigned_abs());
                    cols.max_abs_c_or_1 = Word::from(u64::max(1, (c as i64).unsigned_abs()));
                } else if is_unsigned_word_operation(event.opcode) {
                    cols.abs_remainder = cols.remainder_comp;
                    cols.abs_c = Word::from(event.c as u32);
                    cols.max_abs_c_or_1 = Word::from(u32::max(1, event.c as u32));
                } else {
                    cols.abs_remainder = cols.remainder_comp;
                    cols.abs_c = Word::from(event.c);
                    cols.max_abs_c_or_1 = Word::from(u64::max(1, event.c));
                }

                if is_word_operation(event.opcode) {
                    cols.is_overflow_b.populate((event.b as u32) as u64, i32::MIN as u32 as u64);
                    cols.is_overflow_c.populate((event.c as u32) as u64, -1i32 as u32 as u64);
                } else {
                    cols.is_overflow_b.populate(event.b, i64::MIN as u64);
                    cols.is_overflow_c.populate(event.c, -1i64 as u64);
                }

                cols.b_neg_not_overflow = cols.b_neg * (F::one() - cols.is_overflow);
                cols.b_not_neg_not_overflow =
                    (F::one() - cols.b_neg) * (F::one() - cols.is_overflow);

                // Set the `alu_event` flags.
                cols.abs_c_alu_event = cols.c_neg * cols.is_real;
                cols.abs_rem_alu_event = cols.rem_neg * cols.is_real;

                output.add_u16_range_checks_field(&cols.abs_c.0);
                output.add_u16_range_checks_field(&cols.abs_remainder.0);

                // Populate the c_neg_operation and rem_neg_operation.
                {
                    let mut blu_events = vec![];
                    if cols.abs_c_alu_event.is_one() {
                        cols.c_neg_operation.populate(
                            &mut blu_events,
                            cols.c.to_u64(),
                            cols.abs_c.to_u64(),
                        );
                    }
                    if cols.abs_rem_alu_event.is_one() {
                        cols.rem_neg_operation.populate(
                            &mut blu_events,
                            cols.remainder.to_u64(),
                            cols.abs_remainder.to_u64(),
                        );
                    }
                    output.add_byte_lookup_events(blu_events);
                }

                // Insert the MSB lookup events.
                {
                    let mut blu_events: Vec<ByteLookupEvent> = vec![];

                    if is_word_operation(event.opcode) {
                        cols.b_msb.populate_msb(&mut blu_events, (event.b >> 16) as u16);
                        cols.c_msb.populate_msb(&mut blu_events, (event.c >> 16) as u16);
                        cols.rem_msb.populate_msb(&mut blu_events, (remainder >> 16) as u16);
                        cols.quot_msb.populate_msb(&mut blu_events, (quotient >> 16) as u16);
                    } else {
                        cols.b_msb.populate_msb(&mut blu_events, (b >> 48) as u16);
                        cols.c_msb.populate_msb(&mut blu_events, (c >> 48) as u16);
                        cols.rem_msb.populate_msb(&mut blu_events, (remainder >> 48) as u16);
                    }

                    output.add_byte_lookup_events(blu_events);
                }
            }

            // Calculate the modified multiplicity
            {
                let mut blu_events = vec![];
                cols.remainder_check_multiplicity = cols.is_real * (F::one() - cols.is_c_0.result);
                if cols.remainder_check_multiplicity.is_one() {
                    cols.remainder_lt_operation.populate_unsigned(
                        &mut blu_events,
                        1u64,
                        cols.abs_remainder.to_u64(),
                        cols.max_abs_c_or_1.to_u64(),
                    );
                }

                output.add_byte_lookup_events(blu_events);
            }

            // Calculate c * quotient + remainder.
            {
                let mut blu_events = vec![];
                let mut c_times_quotient_byte = [0u8; 16];

                let c_times_quotient_byte_lower =
                    ((Wrapping(quotient_comp) * Wrapping(c)).0 as u64).to_le_bytes();

                let c_times_quotient_byte_upper = if is_signed_64bit_operation(event.opcode)
                    || is_signed_word_operation(event.opcode)
                {
                    ((((quotient_comp as i64) as i128).wrapping_mul((c as i64) as i128) >> 64)
                        as u64)
                        .to_le_bytes()
                } else {
                    (((quotient_comp as u128 * c as u128) >> 64) as u64).to_le_bytes()
                };

                c_times_quotient_byte[..8].copy_from_slice(&c_times_quotient_byte_lower);
                c_times_quotient_byte[8..].copy_from_slice(&c_times_quotient_byte_upper);

                let c_times_quotient_u16: [u16; LONG_WORD_SIZE] = core::array::from_fn(|i| {
                    u16::from_le_bytes([
                        c_times_quotient_byte[2 * i],
                        c_times_quotient_byte[2 * i + 1],
                    ])
                });

                cols.c_times_quotient = c_times_quotient_u16.map(F::from_canonical_u16);

                cols.c_times_quotient_lower.populate(
                    &mut blu_events,
                    quotient_comp,
                    c,
                    false,
                    false,
                    false,
                );

                if is_signed_64bit_operation(event.opcode) {
                    cols.c_times_quotient_upper.populate(
                        &mut blu_events,
                        quotient_comp,
                        c,
                        true,
                        false,
                        false,
                    );
                }
                if is_unsigned_64bit_operation(event.opcode) {
                    cols.c_times_quotient_upper.populate(
                        &mut blu_events,
                        quotient_comp,
                        c,
                        false,
                        false,
                        false,
                    );
                }

                output.add_byte_lookup_events(blu_events);

                let mut remainder_u16 = [0u32; 8];
                for i in 0..4 {
                    remainder_u16[i] = cols.remainder_comp[i].as_canonical_u32();
                    remainder_u16[i + 4] = cols.rem_neg.as_canonical_u32() * ((1 << 16) - 1);
                }

                // Add remainder to product.
                let mut carry = [0u32; 8];
                let base = 1 << 16;
                for i in 0..LONG_WORD_SIZE {
                    let mut x = c_times_quotient_u16[i] as u32 + remainder_u16[i];
                    if i > 0 {
                        x += carry[i - 1];
                    }
                    carry[i] = x / base;
                    cols.carry[i] = F::from_canonical_u32(carry[i]);
                    output.add_u16_range_check((x & 0xFFFF) as u16);
                }
                // Range check.
                {
                    output.add_u16_range_checks(&[
                        (quotient & 0xFFFF) as u16,
                        (quotient >> 16) as u16,
                        (quotient >> 32) as u16,
                        (quotient >> 48) as u16,
                    ]);
                    output.add_u16_range_checks(&[
                        (remainder & 0xFFFF) as u16,
                        (remainder >> 16) as u16,
                        (remainder >> 32) as u16,
                        (remainder >> 48) as u16,
                    ]);
                    output.add_u16_range_checks(&c_times_quotient_u16);
                }
            }

            if !M::IS_TRUSTED {
                let cols: &mut DivRemCols<F, UserMode> = row.borrow_mut();
                cols.adapter_cols.is_trusted = F::from_bool(!r_record.is_untrusted);
            }
        }

        // Create the padded rows. These are fake rows that don't fail on some sanity checks.
        for row_idx in input.divrem_events.len()..padded_nb_rows {
            let row_start = row_idx * width;
            let row = &mut values[row_start..row_start + width];

            // Zero-initialize
            unsafe {
                core::ptr::write_bytes(row.as_mut_ptr(), 0, width);
            }

            let cols: &mut DivRemCols<F, M> = row.borrow_mut();
            // 0 divided by 1. quotient = remainder = 0.
            cols.is_divu = F::one();
            cols.adapter.op_c_memory.prev_value = Word::from(1u64);
            cols.abs_c[0] = F::one();
            cols.c[0] = F::one();
            cols.max_abs_c_or_1[0] = F::one();
            cols.b_not_neg_not_overflow = F::one();

            cols.is_c_0.populate(1);
        }
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.divrem_events.is_empty()
                && (M::IS_TRUSTED != shard.program.enable_untrusted_programs)
        }
    }
}

impl<F, M: TrustMode> BaseAir<F> for DivRemChip<M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            NUM_DIVREM_COLS_SUPERVISOR
        } else {
            NUM_DIVREM_COLS_USER
        }
    }
}

impl<AB, M> Air<AB> for DivRemChip<M>
where
    AB: SP1CoreAirBuilder,
    M: TrustMode,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &DivRemCols<AB::Var, M> = (*local).borrow();
        let base = AB::F::from_canonical_u32(1 << 16);
        let one: AB::Expr = AB::F::one().into();
        let zero: AB::Expr = AB::F::zero().into();
        let is_word_operation = local.is_divw + local.is_remw + local.is_divuw + local.is_remuw;
        let is_not_word_operation = local.is_divu + local.is_remu + local.is_div + local.is_rem;
        let is_signed_word_operation = local.is_divw + local.is_remw;
        let is_unsigned_word_operation = local.is_divuw + local.is_remuw;
        let is_signed_type = local.is_div + local.is_rem + local.is_divw + local.is_remw;
        let u16_max = AB::F::from_canonical_u16(u16::MAX);
        builder.assert_eq(
            local.is_real_not_word,
            local.is_real * (one.clone() - is_word_operation.clone()),
        );

        // Calculate whether b, remainder, and c are negative.
        {
            // Negative if and only if opcode is signed & MSB = 1.
            let msb_sign_pairs = [
                (local.b_msb.msb, local.b_neg),
                (local.rem_msb.msb, local.rem_neg),
                (local.c_msb.msb, local.c_neg),
            ];

            for msb_sign_pair in msb_sign_pairs.iter() {
                let msb = msb_sign_pair.0;
                let is_negative = msb_sign_pair.1;
                builder.assert_eq(msb * is_signed_type.clone(), is_negative);
            }
        }

        // Assert that the truncated/sign extended b and c align with the original b and c.
        {
            for i in 0..WORD_SIZE / 2 {
                builder.assert_eq(local.adapter.b()[i], local.b[i]);
                builder.assert_eq(local.adapter.c()[i], local.c[i]);
            }
            for i in WORD_SIZE / 2..WORD_SIZE {
                builder.assert_eq(
                    local.b[i],
                    local.adapter.b()[i] * (one.clone() - is_word_operation.clone())
                        + local.b_neg * is_word_operation.clone() * u16_max,
                );
                builder.assert_eq(
                    local.c[i],
                    local.adapter.c()[i] * (one.clone() - is_word_operation.clone())
                        + local.c_neg * is_word_operation.clone() * u16_max,
                );
            }
        }

        // Set up `quotient_comp` and `remainder_comp`.
        {
            // `quotient_comp` is defined as following.
            // - `quotient` for 64-bit operations and signed word operations.
            // - for signed operations, this is the 32-bit result sign-extended to 64 bits.
            // - `quotient` but truncated to 32-bit for unsigned word operations.
            for i in 0..WORD_SIZE / 2 {
                builder.assert_eq(local.quotient_comp[i], local.quotient[i]);
            }

            for i in WORD_SIZE / 2..WORD_SIZE {
                builder
                    .when(is_unsigned_word_operation.clone())
                    .assert_eq(local.quotient_comp[i], AB::Expr::zero());
                builder.when(is_signed_word_operation.clone()).assert_eq(
                    local.quotient_comp[i],
                    local.quot_msb.msb * AB::F::from_canonical_u16(u16::MAX),
                );
                builder.when(is_word_operation.clone()).assert_eq(
                    local.quotient[i],
                    local.quot_msb.msb * AB::F::from_canonical_u16(u16::MAX),
                );
                builder
                    .when(is_not_word_operation.clone())
                    .assert_eq(local.quotient_comp[i], local.quotient[i]);
            }

            // `remainder_comp` is defined as following.
            // - `remainder` for 64-bit operations and signed word operations.
            // - for signed operations, this is the 32-bit result sign-extended to 64 bits.
            // - `remainder_comp` but truncated to 32-bit for unsigned word operations.
            for i in 0..WORD_SIZE / 2 {
                builder.assert_eq(local.remainder_comp[i], local.remainder[i]);
            }

            for i in WORD_SIZE / 2..WORD_SIZE {
                builder
                    .when(is_unsigned_word_operation.clone())
                    .assert_eq(local.remainder_comp[i], AB::Expr::zero());
                builder.when(is_signed_word_operation.clone()).assert_eq(
                    local.remainder_comp[i],
                    local.rem_msb.msb * AB::F::from_canonical_u16(u16::MAX),
                );
                builder.when(is_word_operation.clone()).assert_eq(
                    local.remainder[i],
                    local.rem_msb.msb * AB::F::from_canonical_u16(u16::MAX),
                );
                builder
                    .when(is_not_word_operation.clone())
                    .assert_eq(local.remainder_comp[i], local.remainder[i]);
            }
        }

        // Use the mul operation to compute c * quotient and compare it to local.c_times_quotient.
        {
            let lower_half: [AB::Expr; 4] = [
                local.c_times_quotient[0].into(),
                local.c_times_quotient[1].into(),
                local.c_times_quotient[2].into(),
                local.c_times_quotient[3].into(),
            ];

            // The lower 8 bytes of c_times_quotient are always computed by `MUL` opcode.
            <MulOperation<AB::F> as SP1Operation<AB>>::eval(
                builder,
                MulOperationInput::new(
                    Word(lower_half),
                    local.quotient_comp.map(Into::into),
                    local.c.map(Into::into),
                    local.c_times_quotient_lower,
                    local.is_real.into(),
                    local.is_real.into(), /* local.is_real.into() -
                                           * is_signed_word_operation.clone(), */
                    AB::Expr::zero(),
                    AB::Expr::zero(), // is_signed_word_operation.clone(),
                    AB::Expr::zero(),
                    AB::Expr::zero(),
                ),
            );

            // SAFETY: Since exactly one flag is turned on, `is_mulh` and `is_mulhu` are correct.
            let is_mulh = local.is_div + local.is_rem;
            let is_mulhu = local.is_divu + local.is_remu;

            let upper_half: [AB::Expr; 4] = [
                local.c_times_quotient[4].into(),
                local.c_times_quotient[5].into(),
                local.c_times_quotient[6].into(),
                local.c_times_quotient[7].into(),
            ];

            // The upper 8 bytes of c_times_quotient are computed by `MULH` or `MULHU` opcode.
            <MulOperation<AB::F> as SP1Operation<AB>>::eval(
                builder,
                MulOperationInput::new(
                    Word(upper_half),
                    local.quotient_comp.map(Into::into),
                    local.c.map(Into::into),
                    local.c_times_quotient_upper,
                    local.is_real_not_word.into(),
                    AB::Expr::zero(),
                    is_mulh.clone(),
                    AB::Expr::zero(),
                    is_mulhu.clone(),
                    AB::Expr::zero(),
                ),
            );
        }

        // Calculate is_overflow. This is true if and only if `b, c` are overflow cases, and it's a
        // signed operation. The overflow cases for `b, c` are defined as
        // - For word operations, `b == -2^31` and `c == -1`.
        // - For 64-bit operations, `b == -2^63`, and `c == -1`.
        {
            <IsEqualWordOperation<AB::F> as SP1Operation<AB>>::eval(
                builder,
                IsEqualWordOperationInput::new(
                    local.adapter.b().map(Into::into),
                    Word::from(i64::MIN as u64).map(|x: AB::F| x.into()),
                    local.is_overflow_b,
                    local.is_real_not_word.into(),
                ),
            );

            <IsEqualWordOperation<AB::F> as SP1Operation<AB>>::eval(
                builder,
                IsEqualWordOperationInput::new(
                    local.adapter.c().map(Into::into),
                    Word::from(-1i64 as u64).map(|x: AB::F| x.into()),
                    local.is_overflow_c,
                    local.is_real_not_word.into(),
                ),
            );

            let mut truncated_b = local.adapter.b().map(Into::into);
            let mut truncated_c = local.adapter.c().map(Into::into);
            truncated_b[2] = AB::Expr::zero();
            truncated_c[2] = AB::Expr::zero();
            truncated_b[3] = AB::Expr::zero();
            truncated_c[3] = AB::Expr::zero();

            IsEqualWordOperation::<AB::F>::eval(
                builder,
                IsEqualWordOperationInput::new(
                    truncated_b,
                    Word::from(i32::MIN as u32 as u64).map(|x: AB::F| x.into()),
                    local.is_overflow_b,
                    is_word_operation.clone(),
                ),
            );

            IsEqualWordOperation::<AB::F>::eval(
                builder,
                IsEqualWordOperationInput::new(
                    truncated_c,
                    Word::from(-1i32 as u32 as u64).map(|x: AB::F| x.into()),
                    local.is_overflow_c,
                    is_word_operation.clone(),
                ),
            );

            builder.assert_eq(
                local.is_overflow,
                local.is_overflow_b.is_diff_zero.result
                    * local.is_overflow_c.is_diff_zero.result
                    * is_signed_type.clone(),
            );

            builder.assert_eq(
                local.b_neg_not_overflow,
                local.b_neg * (AB::Expr::one() - local.is_overflow),
            );
            builder.assert_eq(
                local.b_not_neg_not_overflow,
                (AB::Expr::one() - local.b_neg) * (AB::Expr::one() - local.is_overflow),
            );

            // For overflow cases, explicitly constrain the result.
            for i in 0..WORD_SIZE {
                builder.when(local.is_overflow).assert_eq(local.quotient[i], local.b[i]);
                builder.when(local.is_overflow).assert_eq(local.remainder[i], AB::Expr::zero());
            }
        }

        // Add remainder to product c * quotient, and compare it to b.
        {
            let sign_extension = local.rem_neg * AB::F::from_canonical_u16(u16::MAX);
            let mut c_times_quotient_plus_remainder: Vec<AB::Expr> =
                vec![AB::Expr::zero(); LONG_WORD_SIZE];

            // Add remainder to c_times_quotient and propagate carry.
            for i in 0..LONG_WORD_SIZE {
                c_times_quotient_plus_remainder[i] = local.c_times_quotient[i].into();

                // Add remainder.
                if i < WORD_SIZE {
                    c_times_quotient_plus_remainder[i] =
                        c_times_quotient_plus_remainder[i].clone() + local.remainder_comp[i].into();
                } else {
                    // If rem is negative, add 0xff to the upper 4 bytes.
                    c_times_quotient_plus_remainder[i] =
                        c_times_quotient_plus_remainder[i].clone() + sign_extension.clone();
                }

                // Propagate carry.
                // SAFETY: Since carry is a boolean and `c_times_quotient_plus_remainder` are u16s,
                // the results are guaranteed to be correct by the constraints.
                c_times_quotient_plus_remainder[i] =
                    c_times_quotient_plus_remainder[i].clone() - local.carry[i] * base;
                if i > 0 {
                    c_times_quotient_plus_remainder[i] =
                        c_times_quotient_plus_remainder[i].clone() + local.carry[i - 1].into();
                }
            }

            // Compare c_times_quotient_plus_remainder to b by checking each limb.
            for i in 0..LONG_WORD_SIZE {
                if i < WORD_SIZE {
                    builder
                        .when_not(local.is_overflow)
                        .assert_eq(local.b[i], c_times_quotient_plus_remainder[i].clone());
                } else {
                    builder.when_not(local.is_overflow).assert_eq(
                        local.b_neg * AB::F::from_canonical_u16(u16::MAX),
                        c_times_quotient_plus_remainder[i].clone(),
                    );
                }
            }

            builder.slice_range_check_u16(&c_times_quotient_plus_remainder, local.is_real);
        }

        // `a` must equal remainder or quotient depending on the opcode.
        for i in 0..WORD_SIZE {
            builder
                .when(local.is_divu + local.is_div + local.is_divw + local.is_divuw)
                .assert_eq(local.quotient[i], local.a[i]);
            builder
                .when(local.is_remu + local.is_rem + local.is_remw + local.is_remuw)
                .assert_eq(local.remainder[i], local.a[i]);
        }

        // remainder and b must have the same sign. Due to the intricate nature of sign logic in ZK,
        // we will check a slightly stronger condition:
        //
        // 1. If remainder < 0, then b < 0.
        // 2. If remainder > 0, then b >= 0.
        {
            // A number is 0 if and only if the sum of the limbs equals to 0.
            let mut rem_limb_sum = zero.clone();
            for i in 0..WORD_SIZE {
                rem_limb_sum = rem_limb_sum.clone() + local.remainder[i].into();
            }

            // 1. If remainder < 0, then b < 0.
            builder
                .when(local.rem_neg) // rem is negative.
                .assert_one(local.b_neg); // b is negative.

            // 2. If remainder > 0, then b >= 0.
            builder
                .when(rem_limb_sum.clone()) // remainder is nonzero.
                .when(one.clone() - local.rem_neg) // rem is not negative.
                .assert_zero(local.b_neg); // b is not negative.
        }

        // When division by 0, quotient must be u64::MAX per RISC-V spec.
        {
            // Calculate whether c is 0.
            <IsZeroWordOperation<AB::F> as SP1Operation<AB>>::eval(
                builder,
                IsZeroWordOperationInput::new(
                    local.c.map(Into::into),
                    local.is_c_0,
                    local.is_real.into(),
                ),
            );

            // If is_c_0 is true, then quotient must be 0xffffffff_ffffffff = u64::MAX.
            for i in 0..WORD_SIZE {
                builder
                    .when(local.is_c_0.result)
                    .assert_eq(local.quotient[i], AB::F::from_canonical_u16(u16::MAX));
            }

            // If is_c_0 is true, then the remainder must be `local.b`.
            for i in 0..WORD_SIZE {
                builder.when(local.is_c_0.result).assert_eq(local.remainder_comp[i], local.b[i]);
            }
        }

        // Range check remainder. (i.e., |remainder| < |c| when not is_c_0)
        {
            // For each of `c` and `rem`, assert that the absolute value is equal to the original
            // value, if the original value is non-negative or the minimum i64.
            for i in 0..WORD_SIZE {
                // For c, simply check that abs_c equals c when c is not negative
                builder.when_not(local.c_neg).assert_eq(local.c[i], local.abs_c[i]);

                // For remainder, handle both cases with a single condition
                builder
                    .when_not(local.rem_neg)
                    .assert_eq(local.remainder_comp[i], local.abs_remainder[i]);
            }
            // In the case that `c` or `rem` is negative, instead check that their sum is zero.
            <AddOperation<AB::F> as SP1Operation<AB>>::eval(
                builder,
                AddOperationInput::new(
                    local.c.map(Into::into),
                    local.abs_c.map(Into::into),
                    local.c_neg_operation,
                    local.abs_c_alu_event.into(),
                ),
            );
            builder.slice_range_check_u16(&local.abs_c.0, local.is_real);
            builder.when(local.abs_c_alu_event).assert_word_eq(
                Word([zero.clone(), zero.clone(), zero.clone(), zero.clone()]),
                local.c_neg_operation.value,
            );

            <AddOperation<AB::F> as SP1Operation<AB>>::eval(
                builder,
                AddOperationInput::new(
                    local.remainder_comp.map(Into::into),
                    local.abs_remainder.map(Into::into),
                    local.rem_neg_operation,
                    local.abs_rem_alu_event.into(),
                ),
            );
            builder.slice_range_check_u16(&local.abs_remainder.0, local.is_real);
            builder.when(local.abs_rem_alu_event).assert_word_eq(
                Word([zero.clone(), zero.clone(), zero.clone(), zero.clone()]),
                local.rem_neg_operation.value,
            );

            // Check that the absolute value selector columns are computed correctly.
            // This enforces the send multiplicities are zero when `is_real == 0`.
            builder.assert_eq(local.abs_c_alu_event, local.c_neg * local.is_real);
            builder.assert_eq(local.abs_rem_alu_event, local.rem_neg * local.is_real);

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

            // Dispatch abs(remainder) < max(abs(c), 1), this is equivalent to abs(remainder) <
            // abs(c) if not division by 0.
            <LtOperationUnsigned<AB::F> as SP1Operation<AB>>::eval(
                builder,
                LtOperationUnsignedInput::<AB>::new(
                    local.abs_remainder.map(Into::into),
                    local.max_abs_c_or_1.map(Into::into),
                    local.remainder_lt_operation,
                    local.remainder_check_multiplicity.into(),
                ),
            );
            builder
                .when(local.remainder_check_multiplicity)
                .assert_eq(one.clone(), local.remainder_lt_operation.u16_compare_operation.bit);
        }

        // Check that the MSBs are correct.
        {
            //If not word operation, we check the last limb.
            <U16MSBOperation<AB::F> as SP1Operation<AB>>::eval(
                builder,
                U16MSBOperationInput::<AB>::new(
                    local.adapter.b()[WORD_SIZE - 1].into(),
                    local.b_msb,
                    local.is_real_not_word.into(),
                ),
            );
            <U16MSBOperation<AB::F> as SP1Operation<AB>>::eval(
                builder,
                U16MSBOperationInput::<AB>::new(
                    local.adapter.c()[WORD_SIZE - 1].into(),
                    local.c_msb,
                    local.is_real_not_word.into(),
                ),
            );
            <U16MSBOperation<AB::F> as SP1Operation<AB>>::eval(
                builder,
                U16MSBOperationInput::<AB>::new(
                    local.remainder[WORD_SIZE - 1].into(),
                    local.rem_msb,
                    local.is_real_not_word.into(),
                ),
            );

            //If word operation, we check the second limb.
            <U16MSBOperation<AB::F> as SP1Operation<AB>>::eval(
                builder,
                U16MSBOperationInput::<AB>::new(
                    local.adapter.b()[WORD_SIZE / 2 - 1].into(),
                    local.b_msb,
                    is_word_operation.clone(),
                ),
            );
            <U16MSBOperation<AB::F> as SP1Operation<AB>>::eval(
                builder,
                U16MSBOperationInput::<AB>::new(
                    local.adapter.c()[WORD_SIZE / 2 - 1].into(),
                    local.c_msb,
                    is_word_operation.clone(),
                ),
            );
            <U16MSBOperation<AB::F> as SP1Operation<AB>>::eval(
                builder,
                U16MSBOperationInput::<AB>::new(
                    local.remainder[WORD_SIZE / 2 - 1].into(),
                    local.rem_msb,
                    is_word_operation.clone(),
                ),
            );

            // If word operation, we check the second limb of quotient.
            <U16MSBOperation<AB::F> as SP1Operation<AB>>::eval(
                builder,
                U16MSBOperationInput::<AB>::new(
                    local.quotient[WORD_SIZE / 2 - 1].into(),
                    local.quot_msb,
                    is_word_operation.clone(),
                ),
            );
        }

        // Range check all the u16 limbs and boolean carries.
        {
            builder.slice_range_check_u16(&local.quotient.0, local.is_real);
            builder.slice_range_check_u16(&local.remainder.0, local.is_real);

            local.carry.iter().for_each(|carry| {
                builder.assert_bool(*carry);
            });

            builder.slice_range_check_u16(&local.c_times_quotient, local.is_real);
        }

        // Check that the flags are boolean.
        {
            let bool_flags = [
                local.is_div,
                local.is_divu,
                local.is_rem,
                local.is_remu,
                local.is_divw,
                local.is_remw,
                local.is_divuw,
                local.is_remuw,
                local.is_overflow,
                local.is_real_not_word,
                local.b_neg,
                local.b_neg_not_overflow,
                local.b_not_neg_not_overflow,
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
            // SAFETY: All selectors `is_divu`, `is_remu`, `is_div`, `is_rem` are checked to be
            // boolean. Each row has exactly one selector turned on, as their sum is
            // checked to be one. Therefore, the `opcode` matches the corresponding
            // opcode of the instruction.
            builder.assert_eq(
                one.clone(),
                local.is_divu
                    + local.is_remu
                    + local.is_div
                    + local.is_rem
                    + local.is_divw
                    + local.is_remw
                    + local.is_divuw
                    + local.is_remuw,
            );

            // Get the opcode for the operation.
            let opcode = {
                let divu: AB::Expr = AB::F::from_canonical_u32(Opcode::DIVU as u32).into();
                let remu: AB::Expr = AB::F::from_canonical_u32(Opcode::REMU as u32).into();
                let div: AB::Expr = AB::F::from_canonical_u32(Opcode::DIV as u32).into();
                let rem: AB::Expr = AB::F::from_canonical_u32(Opcode::REM as u32).into();
                let divw: AB::Expr = AB::F::from_canonical_u32(Opcode::DIVW as u32).into();
                let remw: AB::Expr = AB::F::from_canonical_u32(Opcode::REMW as u32).into();
                let divuw: AB::Expr = AB::F::from_canonical_u32(Opcode::DIVUW as u32).into();
                let remuw: AB::Expr = AB::F::from_canonical_u32(Opcode::REMUW as u32).into();

                local.is_divu * divu
                    + local.is_remu * remu
                    + local.is_div * div
                    + local.is_rem * rem
                    + local.is_divw * divw
                    + local.is_remw * remw
                    + local.is_divuw * divuw
                    + local.is_remuw * remuw
            };

            // Compute instruction field constants for each opcode
            let funct3 = local.is_divu
                * AB::Expr::from_canonical_u8(Opcode::DIVU.funct3().unwrap())
                + local.is_remu * AB::Expr::from_canonical_u8(Opcode::REMU.funct3().unwrap())
                + local.is_div * AB::Expr::from_canonical_u8(Opcode::DIV.funct3().unwrap())
                + local.is_rem * AB::Expr::from_canonical_u8(Opcode::REM.funct3().unwrap())
                + local.is_divw * AB::Expr::from_canonical_u8(Opcode::DIVW.funct3().unwrap())
                + local.is_remw * AB::Expr::from_canonical_u8(Opcode::REMW.funct3().unwrap())
                + local.is_divuw * AB::Expr::from_canonical_u8(Opcode::DIVUW.funct3().unwrap())
                + local.is_remuw * AB::Expr::from_canonical_u8(Opcode::REMUW.funct3().unwrap());
            let funct7 = local.is_divu
                * AB::Expr::from_canonical_u8(Opcode::DIVU.funct7().unwrap())
                + local.is_remu * AB::Expr::from_canonical_u8(Opcode::REMU.funct7().unwrap())
                + local.is_div * AB::Expr::from_canonical_u8(Opcode::DIV.funct7().unwrap())
                + local.is_rem * AB::Expr::from_canonical_u8(Opcode::REM.funct7().unwrap())
                + local.is_divw * AB::Expr::from_canonical_u8(Opcode::DIVW.funct7().unwrap())
                + local.is_remw * AB::Expr::from_canonical_u8(Opcode::REMW.funct7().unwrap())
                + local.is_divuw * AB::Expr::from_canonical_u8(Opcode::DIVUW.funct7().unwrap())
                + local.is_remuw * AB::Expr::from_canonical_u8(Opcode::REMUW.funct7().unwrap());

            let divu_base = Opcode::DIVU.base_opcode().0;
            let remu_base = Opcode::REMU.base_opcode().0;
            let div_base = Opcode::DIV.base_opcode().0;
            let rem_base = Opcode::REM.base_opcode().0;
            let divw_base = Opcode::DIVW.base_opcode().0;
            let remw_base = Opcode::REMW.base_opcode().0;
            let divuw_base = Opcode::DIVUW.base_opcode().0;
            let remuw_base = Opcode::REMUW.base_opcode().0;

            let divu_base_expr = AB::Expr::from_canonical_u32(divu_base);
            let remu_base_expr = AB::Expr::from_canonical_u32(remu_base);
            let div_base_expr = AB::Expr::from_canonical_u32(div_base);
            let rem_base_expr = AB::Expr::from_canonical_u32(rem_base);

            let divw_base_expr = AB::Expr::from_canonical_u32(divw_base);
            let remw_base_expr = AB::Expr::from_canonical_u32(remw_base);
            let divuw_base_expr = AB::Expr::from_canonical_u32(divuw_base);
            let remuw_base_expr = AB::Expr::from_canonical_u32(remuw_base);

            let calculated_base_opcode = local.is_divu * divu_base_expr
                + local.is_remu * remu_base_expr
                + local.is_div * div_base_expr
                + local.is_rem * rem_base_expr
                + local.is_divw * divw_base_expr
                + local.is_remw * remw_base_expr
                + local.is_divuw * divuw_base_expr
                + local.is_remuw * remuw_base_expr;

            let divu_instr_type = Opcode::DIVU.instruction_type().0 as u32;
            let remu_instr_type = Opcode::REMU.instruction_type().0 as u32;
            let div_instr_type = Opcode::DIV.instruction_type().0 as u32;
            let rem_instr_type = Opcode::REM.instruction_type().0 as u32;
            let divw_instr_type = Opcode::DIVW.instruction_type().0 as u32;
            let remw_instr_type = Opcode::REMW.instruction_type().0 as u32;
            let divuw_instr_type = Opcode::DIVUW.instruction_type().0 as u32;
            let remuw_instr_type = Opcode::REMUW.instruction_type().0 as u32;

            let calculated_instr_type = local.is_divu
                * AB::Expr::from_canonical_u32(divu_instr_type)
                + local.is_remu * AB::Expr::from_canonical_u32(remu_instr_type)
                + local.is_div * AB::Expr::from_canonical_u32(div_instr_type)
                + local.is_rem * AB::Expr::from_canonical_u32(rem_instr_type)
                + local.is_divw * AB::Expr::from_canonical_u32(divw_instr_type)
                + local.is_remw * AB::Expr::from_canonical_u32(remw_instr_type)
                + local.is_divuw * AB::Expr::from_canonical_u32(divuw_instr_type)
                + local.is_remuw * AB::Expr::from_canonical_u32(remuw_instr_type);

            // Constrain the state of the CPU.
            // The program counter and timestamp increment by `4` and `8`.
            <CPUState<AB::F> as SP1Operation<AB>>::eval(
                builder,
                CPUStateInput {
                    cols: local.state,
                    next_pc: [
                        local.state.pc[0] + AB::F::from_canonical_u32(PC_INC),
                        local.state.pc[1].into(),
                        local.state.pc[2].into(),
                    ],
                    clk_increment: AB::Expr::from_canonical_u32(CLK_INC),
                    is_real: local.is_real.into(),
                },
            );

            let mut is_trusted: AB::Expr = local.is_real.into();

            #[cfg(feature = "mprotect")]
            builder.assert_eq(
                builder.extract_public_values().is_untrusted_programs_enabled,
                AB::Expr::from_bool(!M::IS_TRUSTED),
            );

            if !M::IS_TRUSTED {
                let local = main.row_slice(0);
                let local: &DivRemCols<AB::Var, UserMode> = (*local).borrow();

                let instruction = local.adapter.instruction::<AB>(opcode.clone());

                #[cfg(not(feature = "mprotect"))]
                builder.assert_zero(local.is_real);

                eval_untrusted_program(
                    builder,
                    local.state.pc,
                    instruction,
                    [
                        calculated_instr_type.clone(),
                        calculated_base_opcode.clone(),
                        funct3.clone(),
                        funct7.clone(),
                    ],
                    [local.state.clk_high::<AB>(), local.state.clk_low::<AB>()],
                    local.is_real.into(),
                    local.adapter_cols,
                );

                is_trusted = local.adapter_cols.is_trusted.into();
            }

            // This chip is for the case `rd != x0`.
            builder.assert_zero(local.adapter.op_a_0);

            // Constrain the program and register reads.
            let r_reader_input = RTypeReaderInput::<AB, AB::Expr>::new(
                local.state.clk_high::<AB>(),
                local.state.clk_low::<AB>(),
                local.state.pc,
                opcode,
                local.a.map(|x| x.into()),
                local.adapter,
                local.is_real.into(),
                is_trusted,
            );
            <RTypeReader<AB::F> as SP1Operation<AB>>::eval(builder, r_reader_input);
        }
    }
}

// #[cfg(test)]
// mod tests {
//     #![allow(clippy::print_stdout)]

//     use crate::{
//         io::SP1Stdin,
//         riscv::RiscvAir,
//         utils::{run_malicious_test, run_test_machine, setup_test_machine},
//     };
//     use sp1_primitives::SP1Field;
//     use slop_matrix::dense::RowMajorMatrix;
//     use rand::{thread_rng, Rng};
//     use sp1_core_executor::{
//         events::{AluEvent, MemoryRecordEnum},
//         ExecutionRecord, Instruction, Opcode, Program,
//     };
//     use sp1_hypercube::{
//         air::{MachineAir, SP1_PROOF_NUM_PV_ELTS},
//         koala_bear_poseidon2::SP1InnerPcs,
//         Chip, CpuProver, MachineProver, StarkMachine, Val,
//     };

//     use super::DivRemChip;

//     #[test]
//     fn generate_trace() {
//         let mut shard = ExecutionRecord::default();
//         shard.divrem_events = vec![AluEvent::new(0, Opcode::DIVU, 2, 17, 3, false)];
//         let chip = DivRemChip::default();
//         let trace: RowMajorMatrix<SP1Field> =
//             chip.generate_trace(&shard, &mut ExecutionRecord::default());
//         println!("{:?}", trace.values)
//     }

//     fn neg(a: u32) -> u32 {
//         u32::MAX - a + 1
//     }

//     #[test]
//     fn prove_koalabear() {
//         let mut divrem_events: Vec<AluEvent> = Vec::new();

//         let divrems: Vec<(Opcode, u32, u32, u32)> = vec![
//             (Opcode::DIVU, 3, 20, 6),
//             (Opcode::DIVU, 715827879, neg(20), 6),
//             (Opcode::DIVU, 0, 20, neg(6)),
//             (Opcode::DIVU, 0, neg(20), neg(6)),
//             (Opcode::DIVU, 1 << 31, 1 << 31, 1),
//             (Opcode::DIVU, 0, 1 << 31, neg(1)),
//             (Opcode::DIVU, u32::MAX, 1 << 31, 0),
//             (Opcode::DIVU, u32::MAX, 1, 0),
//             (Opcode::DIVU, u32::MAX, 0, 0),
//             (Opcode::REMU, 4, 18, 7),
//             (Opcode::REMU, 6, neg(20), 11),
//             (Opcode::REMU, 23, 23, neg(6)),
//             (Opcode::REMU, neg(21), neg(21), neg(11)),
//             (Opcode::REMU, 5, 5, 0),
//             (Opcode::REMU, neg(1), neg(1), 0),
//             (Opcode::REMU, 0, 0, 0),
//             (Opcode::REM, 7, 16, 9),
//             (Opcode::REM, neg(4), neg(22), 6),
//             (Opcode::REM, 1, 25, neg(3)),
//             (Opcode::REM, neg(2), neg(22), neg(4)),
//             (Opcode::REM, 0, 873, 1),
//             (Opcode::REM, 0, 873, neg(1)),
//             (Opcode::REM, 5, 5, 0),
//             (Opcode::REM, neg(5), neg(5), 0),
//             (Opcode::REM, 0, 0, 0),
//             (Opcode::REM, 0, 0x80000001, neg(1)),
//             (Opcode::DIV, 3, 18, 6),
//             (Opcode::DIV, neg(6), neg(24), 4),
//             (Opcode::DIV, neg(2), 16, neg(8)),
//             (Opcode::DIV, neg(1), 0, 0),
//             (Opcode::DIV, 1 << 31, 1 << 31, neg(1)),
//             (Opcode::REM, 0, 1 << 31, neg(1)),
//         ];
//         for t in divrems.iter() {
//             divrem_events.push(AluEvent::new(0, t.0, t.1, t.2, t.3, false));
//         }

//         // Append more events until we have 1000 tests.
//         for _ in 0..(1000 - divrems.len()) {
//             divrem_events.push(AluEvent::new(0, Opcode::DIVU, 1, 1, 1, false));
//         }

//         let mut shard = ExecutionRecord::default();
//         shard.divrem_events = divrem_events;

//         // Run setup.
//         let air = DivRemChip::default();
//         let config = SP1InnerPcs::new();
//         let chip = Chip::new(air);
//         let (pk, vk) = setup_test_machine(StarkMachine::new(
//             config.clone(),
//             vec![chip],
//             SP1_PROOF_NUM_PV_ELTS,
//             true,
//         ));

//         // Run the test.
//         let air = DivRemChip::default();
//         let chip: Chip<SP1Field, DivRemChip> = Chip::new(air);
//         let machine = StarkMachine::new(config.clone(), vec![chip], SP1_PROOF_NUM_PV_ELTS, true);
//         run_test_machine::<SP1InnerPcs, DivRemChip>(vec![shard], machine, pk,
// vk).unwrap();     }

//     #[test]
//     fn test_malicious_divrem() {
//         const NUM_TESTS: usize = 5;

//         for opcode in [Opcode::DIV, Opcode::DIVU, Opcode::REM, Opcode::REMU] {
//             for _ in 0..NUM_TESTS {
//                 let (correct_op_a, op_b, op_c) = if opcode == Opcode::DIV {
//                     let op_b = thread_rng().gen_range(0..i32::MAX);
//                     let op_c = thread_rng().gen_range(0..i32::MAX);
//                     ((op_b / op_c) as u32, op_b as u32, op_c as u32)
//                 } else if opcode == Opcode::DIVU {
//                     let op_b = thread_rng().gen_range(0..u32::MAX);
//                     let op_c = thread_rng().gen_range(0..u32::MAX);
//                     (op_b / op_c, op_b as u32, op_c as u32)
//                 } else if opcode == Opcode::REM {
//                     let op_b = thread_rng().gen_range(0..i32::MAX);
//                     let op_c = thread_rng().gen_range(0..i32::MAX);
//                     ((op_b % op_c) as u32, op_b as u32, op_c as u32)
//                 } else if opcode == Opcode::REMU {
//                     let op_b = thread_rng().gen_range(0..u32::MAX);
//                     let op_c = thread_rng().gen_range(0..u32::MAX);
//                     (op_b % op_c, op_b as u32, op_c as u32)
//                 } else {
//                     unreachable!()
//                 };

//                 let op_a = thread_rng().gen_range(0..u32::MAX);
//                 assert!(op_a != correct_op_a);

//                 let instructions = vec![
//                     Instruction::new(opcode, 5, op_b, op_c, true, true),
//                     Instruction::new(Opcode::ADD, 10, 0, 0, false, false),
//                 ];

//                 let program = Program::new(instructions, 0, 0);
//                 let stdin = SP1Stdin::new();

//                 type P = CpuProver<SP1InnerPcs, RiscvAir<SP1Field>>;

//                 let malicious_trace_pv_generator = move |prover: &P,
//                                                          record: &mut ExecutionRecord|
//                       -> Vec<(
//                     String,
//                     RowMajorMatrix<Val<SP1InnerPcs>>,
//                 )> {
//                     let mut malicious_record = record.clone();
//                     malicious_record.cpu_events[0].a = op_a;
//                     if let Some(MemoryRecordEnum::Write(mut write_record)) =
//                         malicious_record.cpu_events[0].a_record
//                     {
//                         write_record.value = op_a;
//                     }
//                     malicious_record.divrem_events[0].a = op_a;
//                     prover.generate_traces(&malicious_record)
//                 };

//                 let result =
//                     run_malicious_test::<P>(program, stdin,
// Box::new(malicious_trace_pv_generator));                 assert!(result.is_err() &&
// result.unwrap_err().is_constraints_failing());             }
//         }
//     }
// }
