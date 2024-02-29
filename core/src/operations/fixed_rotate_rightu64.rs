use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::Field;
use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::air::SP1AirBuilder;
use crate::air::Word;
use crate::bytes::utils::shr_carry;
use crate::bytes::ByteLookupEvent;
use crate::bytes::ByteOpcode;
use crate::disassembler::WORD_SIZE;
use crate::runtime::ExecutionRecord;
use p3_field::AbstractField;

/// A set of columns needed to compute `rotateright` of a u64 with a fixed offset R. The u64 is
/// represented as two 32bits limbs. The implementation is inspired by the `FixedRotateRightOperation`.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct FixedRotateRightOperationU64<T> {
    /// The output value.
    pub hi: Word<T>,
    pub lo: Word<T>,

    /// The shift output of `shrcarry` on each byte of a word.
    pub shift: [T; 8],

    /// The carry ouytput of `shrcarry` on each byte of a word.
    pub carry: [T; 8],
}

impl<F: Field> FixedRotateRightOperationU64<F> {
    pub fn nb_bytes_to_shift(rotation: usize) -> usize {
        rotation / 8
    }

    pub fn nb_bits_to_shift(rotation: usize) -> usize {
        rotation % 8
    }

    pub fn carry_multiplier(rotation: usize) -> u32 {
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        1 << (8 - nb_bits_to_shift)
    }

    pub fn populate(
        &mut self,
        record: &mut ExecutionRecord,
        input_lo: u32,
        input_hi: u32,
        rotation: usize,
    ) -> (u32, u32) {
        // compute the input from its 32bits limbs.
        let input = (input_hi as u64) << 32 | input_lo as u64;
        let input_bytes = input.to_le_bytes().map(F::from_canonical_u8);
        let expected = input.rotate_right(rotation as u32);
        let (expected_lo, expected_hi) = (expected as u32, (expected >> 32) as u32);

        // Compute some constants with respect to the rotation needed for the rotation.
        let nb_bytes_to_shift = Self::nb_bytes_to_shift(rotation);
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        let carry_multiplier = F::from_canonical_u32(Self::carry_multiplier(rotation));

        // Perform the byte shift.
        let input_bytes_rotated = [
            input_bytes[nb_bytes_to_shift % (WORD_SIZE * 2)],
            input_bytes[(1 + nb_bytes_to_shift) % (WORD_SIZE * 2)],
            input_bytes[(2 + nb_bytes_to_shift) % (WORD_SIZE * 2)],
            input_bytes[(3 + nb_bytes_to_shift) % (WORD_SIZE * 2)],
            input_bytes[(4 + nb_bytes_to_shift) % (WORD_SIZE * 2)],
            input_bytes[(5 + nb_bytes_to_shift) % (WORD_SIZE * 2)],
            input_bytes[(6 + nb_bytes_to_shift) % (WORD_SIZE * 2)],
            input_bytes[(7 + nb_bytes_to_shift) % (WORD_SIZE * 2)],
        ];

        // For each byte, calculate the shift and carry. If it's not the first byte, calculate the
        // new byte value using the current shifted byte and the last carry.
        let mut first_shift = F::zero();
        let mut last_carry = F::zero();
        for i in (0..WORD_SIZE * 2).rev() {
            let b = input_bytes_rotated[i].to_string().parse::<u8>().unwrap();
            let c = nb_bits_to_shift as u8;

            let (shift, carry) = shr_carry(b, c);

            let byte_event = ByteLookupEvent {
                opcode: ByteOpcode::ShrCarry,
                a1: shift as u32,
                a2: carry as u32,
                b: b as u32,
                c: c as u32,
            };
            record.add_byte_lookup_event(byte_event);

            self.shift[i] = F::from_canonical_u8(shift);
            self.carry[i] = F::from_canonical_u8(carry);

            if i == WORD_SIZE * 2 - 1 {
                first_shift = self.shift[i];
            } else if i < WORD_SIZE {
                self.lo[i] = self.shift[i] + last_carry * carry_multiplier;
            } else {
                self.hi[i - WORD_SIZE] = self.shift[i] + last_carry * carry_multiplier;
            }

            last_carry = self.carry[i];
        }

        // For the first byte, calculate the new byte value using the first shift.
        self.hi[WORD_SIZE - 1] = first_shift + last_carry * carry_multiplier;

        // Check that the expected value is correct.
        assert_eq!(self.lo.to_u32(), expected_lo);
        assert_eq!(self.hi.to_u32(), expected_hi);

        (expected_lo, expected_hi)
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        input_lo: Word<AB::Var>,
        input_hi: Word<AB::Var>,
        rotation: usize,
        cols: FixedRotateRightOperationU64<AB::Var>,
        is_real: AB::Var,
    ) {
        // compute some constants with respect to the rotation needed for the rotation.
        let nb_bytes_to_shift = Self::nb_bytes_to_shift(rotation);
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        let carry_multiplier = AB::F::from_canonical_u32(Self::carry_multiplier(rotation));

        // concatenate the input bytes to compute the input.
        let input = input_lo.into_iter().chain(input_hi).collect::<Vec<_>>();

        // Perform the byte shift.
        let input_bytes_rotated = [
            input[nb_bytes_to_shift % (WORD_SIZE * 2)],
            input[(1 + nb_bytes_to_shift) % (WORD_SIZE * 2)],
            input[(2 + nb_bytes_to_shift) % (WORD_SIZE * 2)],
            input[(3 + nb_bytes_to_shift) % (WORD_SIZE * 2)],
            input[(4 + nb_bytes_to_shift) % (WORD_SIZE * 2)],
            input[(5 + nb_bytes_to_shift) % (WORD_SIZE * 2)],
            input[(6 + nb_bytes_to_shift) % (WORD_SIZE * 2)],
            input[(7 + nb_bytes_to_shift) % (WORD_SIZE * 2)],
        ];

        // For each byte, calculate the shift and carry. If it's not the first byte, calculate the
        // new byte value using the current shifted byte and the last carry.
        let mut first_shift = AB::Expr::zero();
        let mut last_carry = AB::Expr::zero();
        for i in (0..WORD_SIZE * 2).rev() {
            builder.send_byte_pair(
                AB::F::from_canonical_u32(ByteOpcode::ShrCarry as u32),
                cols.shift[i],
                cols.carry[i],
                input_bytes_rotated[i],
                AB::F::from_canonical_usize(nb_bits_to_shift),
                is_real,
            );

            if i == WORD_SIZE * 2 - 1 {
                first_shift = cols.shift[i].into();
            } else if i < WORD_SIZE {
                builder.assert_eq(cols.lo[i], cols.shift[i] + last_carry * carry_multiplier);
            } else {
                builder.assert_eq(
                    cols.hi[i - WORD_SIZE],
                    cols.shift[i] + last_carry * carry_multiplier,
                );
            }

            last_carry = cols.carry[i].into();
        }

        // For the first byte, calculate the new byte using the first shift.
        builder.assert_eq(
            cols.hi[WORD_SIZE - 1],
            first_shift + last_carry * carry_multiplier,
        );
    }
}
