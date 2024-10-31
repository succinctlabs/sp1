//! Verifies left shift.
//!
//! This module implements left shift (b << c) as a combination of bit and byte shifts.
//!
//! The shift amount c is decomposed into two components:
//!
//! - num_bits_to_shift = c % 8: Represents the fine-grained bit-level shift.
//! - num_bytes_to_shift = c // 8: Represents the coarser byte-level shift.
//!
//! Bit shifting is done by multiplying b by 2^num_bits_to_shift. Byte shifting is done by shifting
//! words. The logic looks as follows:
//!
//! c = take the least significant 5 bits of c
//! num_bytes_to_shift = c // 8
//! num_bits_to_shift = c % 8
//!
//! # "Bit shift"
//! bit_shift_multiplier = pow(2, num_bits_to_shift)
//! bit_shift_result = bit_shift_multiplier * b
//!
//! # "Byte shift"
//! for i in range(WORD_SIZE):
//!     if i < num_bytes_to_shift:
//!         assert(a[i] == 0)
//!     else:
//!         assert(a[i] == bit_shift_result[i - num_bytes_to_shift])
//!
//! Notes:
//!
//! - Ideally, we would calculate b * pow(2, c), but pow(2, c) could overflow in F.
//! - Shifting by a multiple of 8 bits is easy (=num_bytes_to_shift) since we just shift words.

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
    ExecutionRecord, Opcode, Program,
};
use sp1_derive::AlignedBorrow;
use sp1_primitives::consts::WORD_SIZE;
use sp1_stark::{air::MachineAir, Word};

use crate::{air::SP1CoreAirBuilder, utils::pad_rows_fixed};

/// The number of main trace columns for `ShiftLeft`.
pub const NUM_SHIFT_LEFT_COLS: usize = size_of::<ShiftLeftCols<u8>>();

/// The number of bits in a byte.
pub const BYTE_SIZE: usize = 8;

/// A chip that implements bitwise operations for the opcodes SLL and SLLI.
#[derive(Default)]
pub struct ShiftLeft;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShiftLeftCols<T> {
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

    /// The least significant byte of `c`. Used to verify `shift_by_n_bits` and `shift_by_n_bytes`.
    pub c_least_sig_byte: [T; BYTE_SIZE],

    /// A boolean array whose `i`th element indicates whether `num_bits_to_shift = i`.
    pub shift_by_n_bits: [T; BYTE_SIZE],

    /// The number to multiply to shift `b` by `num_bits_to_shift`. (i.e., `2^num_bits_to_shift`)
    pub bit_shift_multiplier: T,

    /// The result of multiplying `b` by `bit_shift_multiplier`.
    pub bit_shift_result: [T; WORD_SIZE],

    /// The carry propagated when multiplying `b` by `bit_shift_multiplier`.
    pub bit_shift_result_carry: [T; WORD_SIZE],

    /// A boolean array whose `i`th element indicates whether `num_bytes_to_shift = i`.
    pub shift_by_n_bytes: [T; WORD_SIZE],

    pub is_real: T,
}

impl<F: PrimeField> MachineAir<F> for ShiftLeft {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "ShiftLeft".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let mut rows: Vec<[F; NUM_SHIFT_LEFT_COLS]> = vec![];
        let shift_left_events = input.shift_left_events.clone();
        for event in shift_left_events.iter() {
            let mut row = [F::zero(); NUM_SHIFT_LEFT_COLS];
            let cols: &mut ShiftLeftCols<F> = row.as_mut_slice().borrow_mut();
            let mut blu = Vec::new();
            self.event_to_row(event, cols, &mut blu);
            rows.push(row);
        }

        // Pad the trace to a power of two depending on the proof shape in `input`.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_SHIFT_LEFT_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHIFT_LEFT_COLS,
        );

        // Create the template for the padded rows. These are fake rows that don't fail on some
        // sanity checks.
        let padded_row_template = {
            let mut row = [F::zero(); NUM_SHIFT_LEFT_COLS];
            let cols: &mut ShiftLeftCols<F> = row.as_mut_slice().borrow_mut();
            cols.shift_by_n_bits[0] = F::one();
            cols.shift_by_n_bytes[0] = F::one();
            cols.bit_shift_multiplier = F::one();
            row
        };
        debug_assert!(padded_row_template.len() == NUM_SHIFT_LEFT_COLS);
        for i in input.shift_left_events.len() * NUM_SHIFT_LEFT_COLS..trace.values.len() {
            trace.values[i] = padded_row_template[i % NUM_SHIFT_LEFT_COLS];
        }

        for i in 0..trace.height() {
            let cols: &mut ShiftLeftCols<F> =
                trace.values[i * NUM_SHIFT_LEFT_COLS..(i + 1) * NUM_SHIFT_LEFT_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.shift_left_events.len() / num_cpus::get(), 1);

        let blu_batches = input
            .shift_left_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_SHIFT_LEFT_COLS];
                    let cols: &mut ShiftLeftCols<F> = row.as_mut_slice().borrow_mut();
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
            !shard.shift_left_events.is_empty()
        }
    }
}

impl ShiftLeft {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField>(
        &self,
        event: &AluEvent,
        cols: &mut ShiftLeftCols<F>,
        blu: &mut impl ByteRecord,
    ) {
        let a = event.a.to_le_bytes();
        let b = event.b.to_le_bytes();
        let c = event.c.to_le_bytes();
        cols.shard = F::from_canonical_u32(event.shard);
        cols.a = Word(a.map(F::from_canonical_u8));
        cols.b = Word(b.map(F::from_canonical_u8));
        cols.c = Word(c.map(F::from_canonical_u8));
        cols.is_real = F::one();
        for i in 0..BYTE_SIZE {
            cols.c_least_sig_byte[i] = F::from_canonical_u32((event.c >> i) & 1);
        }

        // Variables for bit shifting.
        let num_bits_to_shift = event.c as usize % BYTE_SIZE;
        for i in 0..BYTE_SIZE {
            cols.shift_by_n_bits[i] = F::from_bool(num_bits_to_shift == i);
        }

        let bit_shift_multiplier = 1u32 << num_bits_to_shift;
        cols.bit_shift_multiplier = F::from_canonical_u32(bit_shift_multiplier);

        let mut carry = 0u32;
        let base = 1u32 << BYTE_SIZE;
        let mut bit_shift_result = [0u8; WORD_SIZE];
        let mut bit_shift_result_carry = [0u8; WORD_SIZE];
        for i in 0..WORD_SIZE {
            let v = b[i] as u32 * bit_shift_multiplier + carry;
            carry = v / base;
            bit_shift_result[i] = (v % base) as u8;
            bit_shift_result_carry[i] = carry as u8;
        }
        cols.bit_shift_result = bit_shift_result.map(F::from_canonical_u8);
        cols.bit_shift_result_carry = bit_shift_result_carry.map(F::from_canonical_u8);

        // Variables for byte shifting.
        let num_bytes_to_shift = (event.c & 0b11111) as usize / BYTE_SIZE;
        for i in 0..WORD_SIZE {
            cols.shift_by_n_bytes[i] = F::from_bool(num_bytes_to_shift == i);
        }

        // Range checks.
        {
            blu.add_u8_range_checks(event.shard, &bit_shift_result);
            blu.add_u8_range_checks(event.shard, &bit_shift_result_carry);
        }

        // Sanity check.
        for i in num_bytes_to_shift..WORD_SIZE {
            debug_assert_eq!(
                cols.bit_shift_result[i - num_bytes_to_shift],
                F::from_canonical_u8(a[i])
            );
        }
    }
}

impl<F> BaseAir<F> for ShiftLeft {
    fn width(&self) -> usize {
        NUM_SHIFT_LEFT_COLS
    }
}

impl<AB> Air<AB> for ShiftLeft
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ShiftLeftCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &ShiftLeftCols<AB::Var> = (*next).borrow();

        let zero: AB::Expr = AB::F::zero().into();
        let one: AB::Expr = AB::F::one().into();
        let base: AB::Expr = AB::F::from_canonical_u32(1 << BYTE_SIZE).into();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        // We first "bit shift" and next we "byte shift". Then we compare the results with a.
        // Finally, we perform some misc checks.

        // Step 1: Perform the fine-grained bit shift (i.e., shifting b by c % 8 bits).

        // Check the sum of c_least_sig_byte[i] * 2^i equals c[0].
        let mut c_byte_sum = zero.clone();
        for i in 0..BYTE_SIZE {
            let val: AB::Expr = AB::F::from_canonical_u32(1 << i).into();
            c_byte_sum = c_byte_sum.clone() + val * local.c_least_sig_byte[i];
        }
        builder.assert_eq(c_byte_sum, local.c[0]);

        // Check shift_by_n_bits[i] is 1 iff i = num_bits_to_shift.
        let mut num_bits_to_shift = zero.clone();

        // 3 is the maximum number of bits necessary to represent num_bits_to_shift as
        // num_bits_to_shift is in [0, 7].
        for i in 0..3 {
            num_bits_to_shift = num_bits_to_shift.clone()
                + local.c_least_sig_byte[i] * AB::F::from_canonical_u32(1 << i);
        }
        for i in 0..BYTE_SIZE {
            builder
                .when(local.shift_by_n_bits[i])
                .assert_eq(num_bits_to_shift.clone(), AB::F::from_canonical_usize(i));
        }

        // Check bit_shift_multiplier = 2^num_bits_to_shift by using shift_by_n_bits.
        for i in 0..BYTE_SIZE {
            builder
                .when(local.shift_by_n_bits[i])
                .assert_eq(local.bit_shift_multiplier, AB::F::from_canonical_usize(1 << i));
        }

        // Check bit_shift_result = b * bit_shift_multiplier by using bit_shift_result_carry to
        // carry-propagate.
        for i in 0..WORD_SIZE {
            let mut v = local.b[i] * local.bit_shift_multiplier
                - local.bit_shift_result_carry[i] * base.clone();
            if i > 0 {
                v = v.clone() + local.bit_shift_result_carry[i - 1].into();
            }
            builder.assert_eq(local.bit_shift_result[i], v);
        }

        // Step 2: Perform the coarser bit shift (i.e., shifting b by c // 8 bits).

        // The two-bit number represented by the 3rd and 4th least significant bits of c is the
        // number of bytes to shift.
        let num_bytes_to_shift =
            local.c_least_sig_byte[3] + local.c_least_sig_byte[4] * AB::F::from_canonical_u32(2);

        // Verify that shift_by_n_bytes[i] = 1 if and only if i = num_bytes_to_shift.
        for i in 0..WORD_SIZE {
            builder
                .when(local.shift_by_n_bytes[i])
                .assert_eq(num_bytes_to_shift.clone(), AB::F::from_canonical_usize(i));
        }

        // The bytes of a must match those of bit_shift_result, taking into account the byte
        // shifting.
        for num_bytes_to_shift in 0..WORD_SIZE {
            let mut shifting = builder.when(local.shift_by_n_bytes[num_bytes_to_shift]);
            for i in 0..WORD_SIZE {
                if i < num_bytes_to_shift {
                    // The first num_bytes_to_shift bytes must be zero.
                    shifting.assert_eq(local.a[i], zero.clone());
                } else {
                    shifting.assert_eq(local.a[i], local.bit_shift_result[i - num_bytes_to_shift]);
                }
            }
        }

        // Step 3: Misc checks such as range checks & bool checks.
        for bit in local.c_least_sig_byte.iter() {
            builder.assert_bool(*bit);
        }

        for shift in local.shift_by_n_bits.iter() {
            builder.assert_bool(*shift);
        }
        builder.assert_eq(
            local.shift_by_n_bits.iter().fold(zero.clone(), |acc, &x| acc + x),
            one.clone(),
        );

        // Range check.
        {
            builder.slice_range_check_u8(&local.bit_shift_result, local.is_real);
            builder.slice_range_check_u8(&local.bit_shift_result_carry, local.is_real);
        }

        for shift in local.shift_by_n_bytes.iter() {
            builder.assert_bool(*shift);
        }

        builder.assert_eq(
            local.shift_by_n_bytes.iter().fold(zero.clone(), |acc, &x| acc + x),
            one.clone(),
        );

        builder.assert_bool(local.is_real);

        // Receive the arguments.
        builder.receive_alu(
            AB::F::from_canonical_u32(Opcode::SLL as u32),
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

    use super::ShiftLeft;

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.shift_left_events = vec![AluEvent::new(0, 0, Opcode::SLL, 16, 8, 1)];
        let chip = ShiftLeft::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut shift_events: Vec<AluEvent> = Vec::new();
        let shift_instructions: Vec<(Opcode, u32, u32, u32)> = vec![
            (Opcode::SLL, 0x00000002, 0x00000001, 1),
            (Opcode::SLL, 0x00000080, 0x00000001, 7),
            (Opcode::SLL, 0x00004000, 0x00000001, 14),
            (Opcode::SLL, 0x80000000, 0x00000001, 31),
            (Opcode::SLL, 0xffffffff, 0xffffffff, 0),
            (Opcode::SLL, 0xfffffffe, 0xffffffff, 1),
            (Opcode::SLL, 0xffffff80, 0xffffffff, 7),
            (Opcode::SLL, 0xffffc000, 0xffffffff, 14),
            (Opcode::SLL, 0x80000000, 0xffffffff, 31),
            (Opcode::SLL, 0x21212121, 0x21212121, 0),
            (Opcode::SLL, 0x42424242, 0x21212121, 1),
            (Opcode::SLL, 0x90909080, 0x21212121, 7),
            (Opcode::SLL, 0x48484000, 0x21212121, 14),
            (Opcode::SLL, 0x80000000, 0x21212121, 31),
            (Opcode::SLL, 0x21212121, 0x21212121, 0xffffffe0),
            (Opcode::SLL, 0x42424242, 0x21212121, 0xffffffe1),
            (Opcode::SLL, 0x90909080, 0x21212121, 0xffffffe7),
            (Opcode::SLL, 0x48484000, 0x21212121, 0xffffffee),
            (Opcode::SLL, 0x00000000, 0x21212120, 0xffffffff),
        ];
        for t in shift_instructions.iter() {
            shift_events.push(AluEvent::new(0, 0, t.0, t.1, t.2, t.3));
        }

        // Append more events until we have 1000 tests.
        for _ in 0..(1000 - shift_instructions.len()) {
            //shift_events.push(AluEvent::new(0, 0, Opcode::SLL, 14, 8, 6));
        }

        let mut shard = ExecutionRecord::default();
        shard.shift_left_events = shift_events;
        let chip = ShiftLeft::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
