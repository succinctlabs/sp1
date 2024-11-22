use p3_field::{AbstractField, Field};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};
use sp1_derive::AlignedBorrow;
use sp1_primitives::consts::WORD_SIZE;
use sp1_stark::{air::SP1AirBuilder, Word};

use crate::bytes::utils::shr_carry;

/// A set of columns needed to compute `>>` of a word with a fixed offset R.
///
/// Note that we decompose shifts into a byte shift and a bit shift.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct FixedShiftRightOperation<T> {
    /// The output value.
    pub value: Word<T>,

    /// The shift output of `shrcarry` on each byte of a word.
    pub shift: Word<T>,

    /// The carry ouytput of `shrcarry` on each byte of a word.
    pub carry: Word<T>,
}

impl<F: Field> FixedShiftRightOperation<F> {
    pub const fn nb_bytes_to_shift(rotation: usize) -> usize {
        rotation / 8
    }

    pub const fn nb_bits_to_shift(rotation: usize) -> usize {
        rotation % 8
    }

    pub const fn carry_multiplier(rotation: usize) -> u32 {
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        1 << (8 - nb_bits_to_shift)
    }

    pub fn populate(&mut self, record: &mut impl ByteRecord, input: u32, rotation: usize) -> u32 {
        let input_bytes = input.to_le_bytes().map(F::from_canonical_u8);
        let expected = input >> rotation;

        // Compute some constants with respect to the rotation needed for the rotation.
        let nb_bytes_to_shift = Self::nb_bytes_to_shift(rotation);
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        let carry_multiplier = F::from_canonical_u32(Self::carry_multiplier(rotation));

        // Perform the byte shift.
        let mut word = [F::zero(); WORD_SIZE];
        for i in 0..WORD_SIZE {
            if i + nb_bytes_to_shift < WORD_SIZE {
                word[i] = input_bytes[(i + nb_bytes_to_shift) % WORD_SIZE];
            }
        }
        let input_bytes_rotated = Word(word);

        // For each byte, calculate the shift and carry. If it's not the first byte, calculate the
        // new byte value using the current shifted byte and the last carry.
        let mut first_shift = F::zero();
        let mut last_carry = F::zero();
        for i in (0..WORD_SIZE).rev() {
            let b = input_bytes_rotated[i].to_string().parse::<u8>().unwrap();
            let c = nb_bits_to_shift as u8;
            let (shift, carry) = shr_carry(b, c);
            let byte_event =
                ByteLookupEvent { opcode: ByteOpcode::ShrCarry, a1: shift as u16, a2: carry, b, c };
            record.add_byte_lookup_event(byte_event);

            self.shift[i] = F::from_canonical_u8(shift);
            self.carry[i] = F::from_canonical_u8(carry);

            if i == WORD_SIZE - 1 {
                first_shift = self.shift[i];
            } else {
                self.value[i] = self.shift[i] + last_carry * carry_multiplier;
            }

            last_carry = self.carry[i];
        }

        // For the first byte, we don't move over the carry as this is a shift, not a rotate.
        self.value[WORD_SIZE - 1] = first_shift;

        // Assert the answer is correct.
        assert_eq!(self.value.to_u32(), expected);

        expected
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        input: Word<AB::Var>,
        rotation: usize,
        cols: FixedShiftRightOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        // Compute some constants with respect to the rotation needed for the rotation.
        let nb_bytes_to_shift = Self::nb_bytes_to_shift(rotation);
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        let carry_multiplier = AB::F::from_canonical_u32(Self::carry_multiplier(rotation));

        // Perform the byte shift.
        let input_bytes_rotated = Word(std::array::from_fn(|i| {
            if i + nb_bytes_to_shift < WORD_SIZE {
                input[(i + nb_bytes_to_shift) % WORD_SIZE].into()
            } else {
                AB::Expr::zero()
            }
        }));

        // For each byte, calculate the shift and carry. If it's not the first byte, calculate the
        // new byte value using the current shifted byte and the last carry.
        let mut first_shift = AB::Expr::zero();
        let mut last_carry = AB::Expr::zero();
        for i in (0..WORD_SIZE).rev() {
            builder.send_byte_pair(
                AB::F::from_canonical_u32(ByteOpcode::ShrCarry as u32),
                cols.shift[i],
                cols.carry[i],
                input_bytes_rotated[i].clone(),
                AB::F::from_canonical_usize(nb_bits_to_shift),
                is_real,
            );

            if i == WORD_SIZE - 1 {
                first_shift = cols.shift[i].into();
            } else {
                builder.assert_eq(cols.value[i], cols.shift[i] + last_carry * carry_multiplier);
            }

            last_carry = cols.carry[i].into();
        }

        // For the first byte, we don't move over the carry as this is a shift, not a rotate.
        builder.assert_eq(cols.value[WORD_SIZE - 1], first_shift);
    }
}
