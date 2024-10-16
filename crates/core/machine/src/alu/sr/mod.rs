//! Logical And Arithmetic Right Shift Verification.
//!
//! Implements verification for a = b >> c, decomposing the shift into bit and byte components:
//!
//! 1. num_bits_to_shift = c % 8: Bit-level shift, achieved by using ShrCarry.
//! 2. num_bytes_to_shift = c // 8: Byte-level shift, shifting entire bytes or words in b.
//!
//! The right shift is verified by reformulating it as (b >> c) = (b >> (num_bytes_to_shift * 8)) >>
//! num_bits_to_shift.
//!
//! The correct leading bits of logical and arithmetic right shifts are verified by sign extending b
//! to 64 bits.
//!
//! c = take the least significant 5 bits of c
//! num_bytes_to_shift = c // 8
//! num_bits_to_shift = c % 8
//!
//! # Sign extend b to 64 bits if SRA.
//! if opcode == SRA:
//!    b = sign_extend_32_bits_to_64_bits(b)
//! else:
//!    b = zero_extend_32_bits_to_64_bits(b)
//!
//!
//! # Byte shift. Leave the num_bytes_to_shift most significant bytes of b 0 for simplicity as it
//! # doesn't affect the correctness of the result.
//! result = [0; LONG_WORD_SIZE]
//! for i in range(LONG_WORD_SIZE - num_bytes_to_shift):
//!     result[i] = b[i + num_bytes_to_shift]
//!
//! # Bit shift.
//! carry_multiplier = 1 << (8 - num_bits_to_shift)
//! last_carry = 0
//! for i in reversed(range(LONG_WORD_SIZE)):
//!     # Shifts a byte to the right and returns both the shifted byte and the bits that carried.
//!     (shifted_byte[i], carry) = shr_carry(result[i], num_bits_to_shift)
//!     result[i] = shifted_byte[i] + last_carry * carry_multiplier
//!     last_carry = carry
//!
//! # The 4 least significant bytes must match a. The 4 most significant bytes of result may be
//! # inaccurate.
//! assert a = result[0..WORD_SIZE]

mod utils;

use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{ParallelIterator, ParallelSlice};
use sp1_core_executor::{
    events::{AluEvent, ByteLookupEvent, ByteRecord},
    ByteOpcode, ExecutionRecord, Opcode, Program,
};
use sp1_derive::AlignedBorrow;
use sp1_primitives::consts::WORD_SIZE;
use sp1_stark::{air::MachineAir, Word};

use crate::{
    air::SP1CoreAirBuilder,
    alu::sr::utils::{nb_bits_to_shift, nb_bytes_to_shift},
    bytes::utils::shr_carry,
    utils::pad_rows_fixed,
};

/// The number of main trace columns for `ShiftRightChip`.
pub const NUM_SHIFT_RIGHT_COLS: usize = size_of::<ShiftRightCols<u8>>();

/// The number of bytes necessary to represent a 64-bit integer.
const LONG_WORD_SIZE: usize = 2 * WORD_SIZE;

/// The number of bits in a byte.
const BYTE_SIZE: usize = 8;

/// A chip that implements bitwise operations for the opcodes SRL and SRA.
#[derive(Default)]
pub struct ShiftRightChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShiftRightCols<T> {
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

    /// A boolean array whose `i`th element indicates whether `num_bits_to_shift = i`.
    pub shift_by_n_bits: [T; BYTE_SIZE],

    /// A boolean array whose `i`th element indicates whether `num_bytes_to_shift = i`.
    pub shift_by_n_bytes: [T; WORD_SIZE],

    /// The result of "byte-shifting" the input operand `b` by `num_bytes_to_shift`.
    pub byte_shift_result: [T; LONG_WORD_SIZE],

    /// The result of "bit-shifting" the byte-shifted input by `num_bits_to_shift`.
    pub bit_shift_result: [T; LONG_WORD_SIZE],

    /// The carry output of `shrcarry` on each byte of `byte_shift_result`.
    pub shr_carry_output_carry: [T; LONG_WORD_SIZE],

    /// The shift byte output of `shrcarry` on each byte of `byte_shift_result`.
    pub shr_carry_output_shifted_byte: [T; LONG_WORD_SIZE],

    /// The most significant bit of `b`.
    pub b_msb: T,

    /// The least significant byte of `c`. Used to verify `shift_by_n_bits` and `shift_by_n_bytes`.
    pub c_least_sig_byte: [T; BYTE_SIZE],

    /// If the opcode is SRL.
    pub is_srl: T,

    /// If the opcode is SRA.
    pub is_sra: T,

    /// Selector to know whether this row is enabled.
    pub is_real: T,
}

impl<F: PrimeField> MachineAir<F> for ShiftRightChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "ShiftRight".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let mut rows: Vec<[F; NUM_SHIFT_RIGHT_COLS]> = Vec::new();
        let sr_events = input.shift_right_events.clone();
        for event in sr_events.iter() {
            assert!(event.opcode == Opcode::SRL || event.opcode == Opcode::SRA);
            let mut row = [F::zero(); NUM_SHIFT_RIGHT_COLS];
            let cols: &mut ShiftRightCols<F> = row.as_mut_slice().borrow_mut();
            let mut blu = Vec::new();
            self.event_to_row(event, cols, &mut blu);
            rows.push(row);
        }

        // Pad the trace to a power of two depending on the proof shape in `input`.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_SHIFT_RIGHT_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHIFT_RIGHT_COLS,
        );

        // Create the template for the padded rows. These are fake rows that don't fail on some
        // sanity checks.
        let padded_row_template = {
            let mut row = [F::zero(); NUM_SHIFT_RIGHT_COLS];
            let cols: &mut ShiftRightCols<F> = row.as_mut_slice().borrow_mut();
            // Shift 0 by 0 bits and 0 bytes.
            // cols.is_srl = F::one();
            cols.shift_by_n_bits[0] = F::one();
            cols.shift_by_n_bytes[0] = F::one();
            row
        };
        debug_assert!(padded_row_template.len() == NUM_SHIFT_RIGHT_COLS);
        for i in input.shift_right_events.len() * NUM_SHIFT_RIGHT_COLS..trace.values.len() {
            trace.values[i] = padded_row_template[i % NUM_SHIFT_RIGHT_COLS];
        }

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut ShiftRightCols<F> =
                trace.values[i * NUM_SHIFT_RIGHT_COLS..(i + 1) * NUM_SHIFT_RIGHT_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.shift_right_events.len() / num_cpus::get(), 1);

        let blu_batches = input
            .shift_right_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_SHIFT_RIGHT_COLS];
                    let cols: &mut ShiftRightCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(event, cols, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_sharded_byte_lookup_events(blu_batches.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.shift_right_events.is_empty()
        }
    }
}

impl ShiftRightChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField>(
        &self,
        event: &AluEvent,
        cols: &mut ShiftRightCols<F>,
        blu: &mut impl ByteRecord,
    ) {
        // Initialize cols with basic operands and flags derived from the current event.
        {
            cols.shard = F::from_canonical_u32(event.shard);
            cols.a = Word::from(event.a);
            cols.b = Word::from(event.b);
            cols.c = Word::from(event.c);

            cols.b_msb = F::from_canonical_u32((event.b >> 31) & 1);

            cols.is_srl = F::from_bool(event.opcode == Opcode::SRL);
            cols.is_sra = F::from_bool(event.opcode == Opcode::SRA);

            cols.is_real = F::one();

            for i in 0..BYTE_SIZE {
                cols.c_least_sig_byte[i] = F::from_canonical_u32((event.c >> i) & 1);
            }

            // Insert the MSB lookup event.
            let most_significant_byte = event.b.to_le_bytes()[WORD_SIZE - 1];
            blu.add_byte_lookup_events(vec![ByteLookupEvent {
                shard: event.shard,
                opcode: ByteOpcode::MSB,
                a1: ((most_significant_byte >> 7) & 1) as u16,
                a2: 0,
                b: most_significant_byte,
                c: 0,
            }]);
        }

        let num_bytes_to_shift = nb_bytes_to_shift(event.c);
        let num_bits_to_shift = nb_bits_to_shift(event.c);

        // Byte shifting.
        let mut byte_shift_result = [0u8; LONG_WORD_SIZE];
        {
            for i in 0..WORD_SIZE {
                cols.shift_by_n_bytes[i] = F::from_bool(num_bytes_to_shift == i);
            }
            let sign_extended_b = {
                if event.opcode == Opcode::SRA {
                    // Sign extension is necessary only for arithmetic right shift.
                    ((event.b as i32) as i64).to_le_bytes()
                } else {
                    (event.b as u64).to_le_bytes()
                }
            };

            for i in 0..LONG_WORD_SIZE {
                if i + num_bytes_to_shift < LONG_WORD_SIZE {
                    byte_shift_result[i] = sign_extended_b[i + num_bytes_to_shift];
                }
            }
            cols.byte_shift_result = byte_shift_result.map(F::from_canonical_u8);
        }

        // Bit shifting.
        {
            for i in 0..BYTE_SIZE {
                cols.shift_by_n_bits[i] = F::from_bool(num_bits_to_shift == i);
            }
            let carry_multiplier = 1 << (8 - num_bits_to_shift);
            let mut last_carry = 0u32;
            let mut bit_shift_result = [0u8; LONG_WORD_SIZE];
            let mut shr_carry_output_carry = [0u8; LONG_WORD_SIZE];
            let mut shr_carry_output_shifted_byte = [0u8; LONG_WORD_SIZE];
            for i in (0..LONG_WORD_SIZE).rev() {
                let (shift, carry) = shr_carry(byte_shift_result[i], num_bits_to_shift as u8);

                let byte_event = ByteLookupEvent {
                    shard: event.shard,
                    opcode: ByteOpcode::ShrCarry,
                    a1: shift as u16,
                    a2: carry,
                    b: byte_shift_result[i],
                    c: num_bits_to_shift as u8,
                };
                blu.add_byte_lookup_event(byte_event);

                shr_carry_output_carry[i] = carry;
                shr_carry_output_shifted_byte[i] = shift;
                bit_shift_result[i] = ((shift as u32 + last_carry * carry_multiplier) & 0xff) as u8;
                last_carry = carry as u32;
            }
            cols.bit_shift_result = bit_shift_result.map(F::from_canonical_u8);
            cols.shr_carry_output_carry = shr_carry_output_carry.map(F::from_canonical_u8);
            cols.shr_carry_output_shifted_byte =
                shr_carry_output_shifted_byte.map(F::from_canonical_u8);
            for i in 0..WORD_SIZE {
                debug_assert_eq!(cols.a[i], cols.bit_shift_result[i].clone());
            }
            // Range checks.
            blu.add_u8_range_checks(event.shard, &byte_shift_result);
            blu.add_u8_range_checks(event.shard, &bit_shift_result);
            blu.add_u8_range_checks(event.shard, &shr_carry_output_carry);
            blu.add_u8_range_checks(event.shard, &shr_carry_output_shifted_byte);
        }
    }
}

impl<F> BaseAir<F> for ShiftRightChip {
    fn width(&self) -> usize {
        NUM_SHIFT_RIGHT_COLS
    }
}

impl<AB> Air<AB> for ShiftRightChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ShiftRightCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &ShiftRightCols<AB::Var> = (*next).borrow();
        let zero: AB::Expr = AB::F::zero().into();
        let one: AB::Expr = AB::F::one().into();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        // Check that the MSB of most_significant_byte matches local.b_msb using lookup.
        {
            let byte = local.b[WORD_SIZE - 1];
            let opcode = AB::F::from_canonical_u32(ByteOpcode::MSB as u32);
            let msb = local.b_msb;
            builder.send_byte(opcode, msb, byte, zero.clone(), local.is_real);
        }

        // Calculate the number of bits and bytes to shift by from c.
        {
            // The sum of c_least_sig_byte[i] * 2^i must match c[0].
            let mut c_byte_sum = AB::Expr::zero();
            for i in 0..BYTE_SIZE {
                let val: AB::Expr = AB::F::from_canonical_u32(1 << i).into();
                c_byte_sum += val * local.c_least_sig_byte[i];
            }
            builder.assert_eq(c_byte_sum, local.c[0]);

            // Number of bits to shift.

            // The 3-bit number represented by the 3 least significant bits of c equals the number
            // of bits to shift.
            let mut num_bits_to_shift = AB::Expr::zero();
            for i in 0..3 {
                num_bits_to_shift += local.c_least_sig_byte[i] * AB::F::from_canonical_u32(1 << i);
            }
            for i in 0..BYTE_SIZE {
                builder
                    .when(local.shift_by_n_bits[i])
                    .assert_eq(num_bits_to_shift.clone(), AB::F::from_canonical_usize(i));
            }

            // Exactly one of the shift_by_n_bits must be 1.
            builder.assert_eq(
                local.shift_by_n_bits.iter().fold(zero.clone(), |acc, &x| acc + x),
                one.clone(),
            );

            // The 2-bit number represented by the 3rd and 4th least significant bits of c is the
            // number of bytes to shift.
            let num_bytes_to_shift = local.c_least_sig_byte[3]
                + local.c_least_sig_byte[4] * AB::F::from_canonical_u32(2);

            // If shift_by_n_bytes[i] = 1, then i = num_bytes_to_shift.
            for i in 0..WORD_SIZE {
                builder
                    .when(local.shift_by_n_bytes[i])
                    .assert_eq(num_bytes_to_shift.clone(), AB::F::from_canonical_usize(i));
            }

            // Exactly one of the shift_by_n_bytes must be 1.
            builder.assert_eq(
                local.shift_by_n_bytes.iter().fold(zero.clone(), |acc, &x| acc + x),
                one.clone(),
            );
        }

        // Byte shift the sign-extended b.
        {
            // The leading bytes of b should be 0xff if b's MSB is 1 & opcode = SRA, 0 otherwise.
            let leading_byte = local.is_sra * local.b_msb * AB::Expr::from_canonical_u8(0xff);
            let mut sign_extended_b: Vec<AB::Expr> = vec![];
            for i in 0..WORD_SIZE {
                sign_extended_b.push(local.b[i].into());
            }
            for _ in 0..WORD_SIZE {
                sign_extended_b.push(leading_byte.clone());
            }

            // Shift the bytes of sign_extended_b by num_bytes_to_shift.
            for num_bytes_to_shift in 0..WORD_SIZE {
                for i in 0..(LONG_WORD_SIZE - num_bytes_to_shift) {
                    builder.when(local.shift_by_n_bytes[num_bytes_to_shift]).assert_eq(
                        local.byte_shift_result[i],
                        sign_extended_b[i + num_bytes_to_shift].clone(),
                    );
                }
            }
        }

        // Bit shift the byte_shift_result using ShrCarry, and compare the result to a.
        {
            // The carry multiplier is 2^(8 - num_bits_to_shift).
            let mut carry_multiplier = AB::Expr::from_canonical_u8(0);
            for i in 0..BYTE_SIZE {
                carry_multiplier +=
                    AB::Expr::from_canonical_u32(1u32 << (8 - i)) * local.shift_by_n_bits[i];
            }

            // The 3-bit number represented by the 3 least significant bits of c equals the number
            // of bits to shift.
            let mut num_bits_to_shift = AB::Expr::zero();
            for i in 0..3 {
                num_bits_to_shift += local.c_least_sig_byte[i] * AB::F::from_canonical_u32(1 << i);
            }

            // Calculate ShrCarry.
            for i in (0..LONG_WORD_SIZE).rev() {
                builder.send_byte_pair(
                    AB::F::from_canonical_u32(ByteOpcode::ShrCarry as u32),
                    local.shr_carry_output_shifted_byte[i],
                    local.shr_carry_output_carry[i],
                    local.byte_shift_result[i],
                    num_bits_to_shift.clone(),
                    local.is_real,
                );
            }

            // Use the results of ShrCarry to calculate the bit shift result.
            for i in (0..LONG_WORD_SIZE).rev() {
                let mut v: AB::Expr = local.shr_carry_output_shifted_byte[i].into();
                if i + 1 < LONG_WORD_SIZE {
                    v += local.shr_carry_output_carry[i + 1] * carry_multiplier.clone();
                }
                builder.assert_eq(v, local.bit_shift_result[i]);
            }
        }

        // The 4 least significant bytes must match a. The 4 most significant bytes of result may be
        // inaccurate.
        {
            for i in 0..WORD_SIZE {
                builder.assert_eq(local.a[i], local.bit_shift_result[i]);
            }
        }

        // Check that the flags are indeed boolean.
        {
            let flags = [local.is_srl, local.is_sra, local.is_real, local.b_msb];
            for flag in flags.iter() {
                builder.assert_bool(*flag);
            }
            for shift_by_n_byte in local.shift_by_n_bytes.iter() {
                builder.assert_bool(*shift_by_n_byte);
            }
            for shift_by_n_bit in local.shift_by_n_bits.iter() {
                builder.assert_bool(*shift_by_n_bit);
            }
            for bit in local.c_least_sig_byte.iter() {
                builder.assert_bool(*bit);
            }
        }

        // Range check bytes.
        {
            let long_words = [
                local.byte_shift_result,
                local.bit_shift_result,
                local.shr_carry_output_carry,
                local.shr_carry_output_shifted_byte,
            ];

            for long_word in long_words.iter() {
                builder.slice_range_check_u8(long_word, local.is_real);
            }
        }

        // Check that the operation flags are boolean.
        builder.assert_bool(local.is_srl);
        builder.assert_bool(local.is_sra);
        builder.assert_bool(local.is_real);

        // Check that is_real is the sum of the two operation flags.
        builder.assert_eq(local.is_srl + local.is_sra, local.is_real);

        // Receive the arguments.
        builder.receive_alu(
            local.is_srl * AB::F::from_canonical_u32(Opcode::SRL as u32)
                + local.is_sra * AB::F::from_canonical_u32(Opcode::SRA as u32),
            local.a,
            local.b,
            local.c,
            local.shard,
            local.nonce,
            local.is_real,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use sp1_core_executor::{events::AluEvent, ExecutionRecord, Opcode};
    use sp1_stark::{air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig};

    use super::ShiftRightChip;

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.shift_right_events = vec![AluEvent::new(0, 0, Opcode::SRL, 6, 12, 1)];
        let chip = ShiftRightChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let shifts = vec![
            (Opcode::SRL, 0xffff8000, 0xffff8000, 0),
            (Opcode::SRL, 0x7fffc000, 0xffff8000, 1),
            (Opcode::SRL, 0x01ffff00, 0xffff8000, 7),
            (Opcode::SRL, 0x0003fffe, 0xffff8000, 14),
            (Opcode::SRL, 0x0001ffff, 0xffff8001, 15),
            (Opcode::SRL, 0xffffffff, 0xffffffff, 0),
            (Opcode::SRL, 0x7fffffff, 0xffffffff, 1),
            (Opcode::SRL, 0x01ffffff, 0xffffffff, 7),
            (Opcode::SRL, 0x0003ffff, 0xffffffff, 14),
            (Opcode::SRL, 0x00000001, 0xffffffff, 31),
            (Opcode::SRL, 0x21212121, 0x21212121, 0),
            (Opcode::SRL, 0x10909090, 0x21212121, 1),
            (Opcode::SRL, 0x00424242, 0x21212121, 7),
            (Opcode::SRL, 0x00008484, 0x21212121, 14),
            (Opcode::SRL, 0x00000000, 0x21212121, 31),
            (Opcode::SRL, 0x21212121, 0x21212121, 0xffffffe0),
            (Opcode::SRL, 0x10909090, 0x21212121, 0xffffffe1),
            (Opcode::SRL, 0x00424242, 0x21212121, 0xffffffe7),
            (Opcode::SRL, 0x00008484, 0x21212121, 0xffffffee),
            (Opcode::SRL, 0x00000000, 0x21212121, 0xffffffff),
            (Opcode::SRA, 0x00000000, 0x00000000, 0),
            (Opcode::SRA, 0xc0000000, 0x80000000, 1),
            (Opcode::SRA, 0xff000000, 0x80000000, 7),
            (Opcode::SRA, 0xfffe0000, 0x80000000, 14),
            (Opcode::SRA, 0xffffffff, 0x80000001, 31),
            (Opcode::SRA, 0x7fffffff, 0x7fffffff, 0),
            (Opcode::SRA, 0x3fffffff, 0x7fffffff, 1),
            (Opcode::SRA, 0x00ffffff, 0x7fffffff, 7),
            (Opcode::SRA, 0x0001ffff, 0x7fffffff, 14),
            (Opcode::SRA, 0x00000000, 0x7fffffff, 31),
            (Opcode::SRA, 0x81818181, 0x81818181, 0),
            (Opcode::SRA, 0xc0c0c0c0, 0x81818181, 1),
            (Opcode::SRA, 0xff030303, 0x81818181, 7),
            (Opcode::SRA, 0xfffe0606, 0x81818181, 14),
            (Opcode::SRA, 0xffffffff, 0x81818181, 31),
        ];
        let mut shift_events: Vec<AluEvent> = Vec::new();
        for t in shifts.iter() {
            shift_events.push(AluEvent::new(0, 0, t.0, t.1, t.2, t.3));
        }
        let mut shard = ExecutionRecord::default();
        shard.shift_right_events = shift_events;
        let chip = ShiftRightChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
