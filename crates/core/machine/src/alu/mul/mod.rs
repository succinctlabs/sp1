//! Implementation to check that b * c = product.
//!
//! We first extend the operands to 64 bits. We sign-extend them if the op code is signed. Then we
//! calculate the un-carried product and propagate the carry. Finally, we check that the appropriate
//! bits of the product match the result.
//!
//! b_64 = sign_extend(b) if signed operation else b
//! c_64 = sign_extend(c) if signed operation else c
//!
//! m = []
//! # 64-bit integers have 8 limbs.
//! # Calculate un-carried product.
//! for i in 0..8:
//!     for j in 0..8:
//!         if i + j < 8:
//!             m[i + j] += b_64[i] * c_64[j]
//!
//! # Propagate carry
//! for i in 0..8:
//!     x = m[i]
//!     if i > 0:
//!         x += carry[i - 1]
//!     carry[i] = x / 256
//!     m[i] = x % 256
//!
//! if upper_half:
//!     assert_eq(a, m[4..8])
//! if lower_half:
//!     assert_eq(a, m[0..4])

mod utils;

use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{ParallelIterator, ParallelSlice};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode, ExecutionRecord, Opcode, Program,
};
use sp1_derive::AlignedBorrow;
use sp1_primitives::consts::WORD_SIZE;
use sp1_stark::{air::MachineAir, MachineRecord, Word};

use crate::{air::SP1CoreAirBuilder, alu::mul::utils::get_msb, utils::pad_rows_fixed};

/// The number of main trace columns for `MulChip`.
pub const NUM_MUL_COLS: usize = size_of::<MulCols<u8>>();

/// The number of digits in the product is at most the sum of the number of digits in the
/// multiplicands.
const PRODUCT_SIZE: usize = 2 * WORD_SIZE;

/// The number of bits in a byte.
const BYTE_SIZE: usize = 8;

/// The mask for a byte.
const BYTE_MASK: u8 = 0xff;

/// A chip that implements multiplication for the multiplication opcodes.
#[derive(Default)]
pub struct MulChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MulCols<T> {
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

    /// Trace.
    pub carry: [T; PRODUCT_SIZE],

    /// An array storing the product of `b * c` after the carry propagation.
    pub product: [T; PRODUCT_SIZE],

    /// The most significant bit of `b`.
    pub b_msb: T,

    /// The most significant bit of `c`.
    pub c_msb: T,

    /// The sign extension of `b`.
    pub b_sign_extend: T,

    /// The sign extension of `c`.
    pub c_sign_extend: T,

    /// Flag indicating whether the opcode is `MUL` (`u32 x u32`).
    pub is_mul: T,

    /// Flag indicating whether the opcode is `MULH` (`i32 x i32`, upper half).
    pub is_mulh: T,

    /// Flag indicating whether the opcode is `MULHU` (`u32 x u32`, upper half).
    pub is_mulhu: T,

    /// Flag indicating whether the opcode is `MULHSU` (`i32 x u32`, upper half).
    pub is_mulhsu: T,

    /// Selector to know whether this row is enabled.
    pub is_real: T,
}

impl<F: PrimeField> MachineAir<F> for MulChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Mul".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mul_events = input.mul_events.clone();
        // Compute the chunk size based on the number of events and the number of CPUs.
        let chunk_size = std::cmp::max(mul_events.len() / num_cpus::get(), 1);

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let rows_and_records = mul_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut record = ExecutionRecord::default();
                let rows = events
                    .iter()
                    .map(|event| {
                        // Ensure that the opcode is MUL, MULHU, MULH, or MULHSU.
                        assert!(
                            event.opcode == Opcode::MUL
                                || event.opcode == Opcode::MULHU
                                || event.opcode == Opcode::MULH
                                || event.opcode == Opcode::MULHSU
                        );
                        let mut row = [F::zero(); NUM_MUL_COLS];
                        let cols: &mut MulCols<F> = row.as_mut_slice().borrow_mut();

                        let a_word = event.a.to_le_bytes();
                        let b_word = event.b.to_le_bytes();
                        let c_word = event.c.to_le_bytes();

                        let mut b = b_word.to_vec();
                        let mut c = c_word.to_vec();

                        // Handle b and c's signs.
                        {
                            let b_msb = get_msb(b_word);
                            cols.b_msb = F::from_canonical_u8(b_msb);
                            let c_msb = get_msb(c_word);
                            cols.c_msb = F::from_canonical_u8(c_msb);

                            // If b is signed and it is negative, sign extend b.
                            if (event.opcode == Opcode::MULH || event.opcode == Opcode::MULHSU)
                                && b_msb == 1
                            {
                                cols.b_sign_extend = F::one();
                                b.resize(PRODUCT_SIZE, BYTE_MASK);
                            }

                            // If c is signed and it is negative, sign extend c.
                            if event.opcode == Opcode::MULH && c_msb == 1 {
                                cols.c_sign_extend = F::one();
                                c.resize(PRODUCT_SIZE, BYTE_MASK);
                            }

                            // Insert the MSB lookup events.
                            {
                                let words = [b_word, c_word];
                                let mut blu_events: Vec<ByteLookupEvent> = vec![];
                                for word in words.iter() {
                                    let most_significant_byte = word[WORD_SIZE - 1];
                                    blu_events.push(ByteLookupEvent {
                                        shard: event.shard,
                                        opcode: ByteOpcode::MSB,
                                        a1: get_msb(*word) as u16,
                                        a2: 0,
                                        b: most_significant_byte,
                                        c: 0,
                                    });
                                }
                                record.add_byte_lookup_events(blu_events);
                            }
                        }

                        let mut product = [0u32; PRODUCT_SIZE];
                        for i in 0..b.len() {
                            for j in 0..c.len() {
                                if i + j < PRODUCT_SIZE {
                                    product[i + j] += (b[i] as u32) * (c[j] as u32);
                                }
                            }
                        }

                        // Calculate the correct product using the `product` array. We store the
                        // correct carry value for verification.
                        let base = (1 << BYTE_SIZE) as u32;
                        let mut carry = [0u32; PRODUCT_SIZE];
                        for i in 0..PRODUCT_SIZE {
                            carry[i] = product[i] / base;
                            product[i] %= base;
                            if i + 1 < PRODUCT_SIZE {
                                product[i + 1] += carry[i];
                            }
                            cols.carry[i] = F::from_canonical_u32(carry[i]);
                        }

                        cols.product = product.map(F::from_canonical_u32);
                        cols.a = Word(a_word.map(F::from_canonical_u8));
                        cols.b = Word(b_word.map(F::from_canonical_u8));
                        cols.c = Word(c_word.map(F::from_canonical_u8));
                        cols.is_real = F::one();
                        cols.is_mul = F::from_bool(event.opcode == Opcode::MUL);
                        cols.is_mulh = F::from_bool(event.opcode == Opcode::MULH);
                        cols.is_mulhu = F::from_bool(event.opcode == Opcode::MULHU);
                        cols.is_mulhsu = F::from_bool(event.opcode == Opcode::MULHSU);
                        cols.shard = F::from_canonical_u32(event.shard);

                        // Range check.
                        {
                            record.add_u16_range_checks(event.shard, &carry.map(|x| x as u16));
                            record.add_u8_range_checks(event.shard, &product.map(|x| x as u8));
                        }
                        row
                    })
                    .collect::<Vec<_>>();
                (rows, record)
            })
            .collect::<Vec<_>>();

        // Generate the trace rows for each event.
        let mut rows: Vec<[F; NUM_MUL_COLS]> = vec![];
        for mut row_and_record in rows_and_records {
            rows.extend(row_and_record.0);
            output.append(&mut row_and_record.1);
        }

        // Pad the trace to a power of two depending on the proof shape in `input`.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_MUL_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_MUL_COLS);

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut MulCols<F> =
                trace.values[i * NUM_MUL_COLS..(i + 1) * NUM_MUL_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.mul_events.is_empty()
        }
    }
}

impl<F> BaseAir<F> for MulChip {
    fn width(&self) -> usize {
        NUM_MUL_COLS
    }
}

impl<AB> Air<AB> for MulChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MulCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &MulCols<AB::Var> = (*next).borrow();
        let base = AB::F::from_canonical_u32(1 << 8);

        let zero: AB::Expr = AB::F::zero().into();
        let one: AB::Expr = AB::F::one().into();
        let byte_mask = AB::F::from_canonical_u8(BYTE_MASK);

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        // Calculate the MSBs.
        let (b_msb, c_msb) = {
            let msb_pairs =
                [(local.b_msb, local.b[WORD_SIZE - 1]), (local.c_msb, local.c[WORD_SIZE - 1])];
            let opcode = AB::F::from_canonical_u32(ByteOpcode::MSB as u32);
            for msb_pair in msb_pairs.iter() {
                let msb = msb_pair.0;
                let byte = msb_pair.1;
                builder.send_byte(opcode, msb, byte, zero.clone(), local.is_real);
            }
            (local.b_msb, local.c_msb)
        };

        // Calculate whether to extend b and c's sign.
        let (b_sign_extend, c_sign_extend) = {
            // MULH or MULHSU
            let is_b_i32 = local.is_mulh + local.is_mulhsu - local.is_mulh * local.is_mulhsu;

            let is_c_i32 = local.is_mulh;

            builder.assert_eq(local.b_sign_extend, is_b_i32 * b_msb);
            builder.assert_eq(local.c_sign_extend, is_c_i32 * c_msb);
            (local.b_sign_extend, local.c_sign_extend)
        };

        // Sign extend local.b and local.c whenever appropriate.
        let (b, c) = {
            let mut b: Vec<AB::Expr> = vec![AB::F::zero().into(); PRODUCT_SIZE];
            let mut c: Vec<AB::Expr> = vec![AB::F::zero().into(); PRODUCT_SIZE];
            for i in 0..PRODUCT_SIZE {
                if i < WORD_SIZE {
                    b[i] = local.b[i].into();
                    c[i] = local.c[i].into();
                } else {
                    b[i] = b_sign_extend * byte_mask;
                    c[i] = c_sign_extend * byte_mask;
                }
            }
            (b, c)
        };

        // Compute the uncarried product b(x) * c(x) = m(x).
        let mut m: Vec<AB::Expr> = vec![AB::F::zero().into(); PRODUCT_SIZE];
        for i in 0..PRODUCT_SIZE {
            for j in 0..PRODUCT_SIZE {
                if i + j < PRODUCT_SIZE {
                    m[i + j] = m[i + j].clone() + b[i].clone() * c[j].clone();
                }
            }
        }

        // Propagate carry.
        let product = {
            for i in 0..PRODUCT_SIZE {
                if i == 0 {
                    builder.assert_eq(local.product[i], m[i].clone() - local.carry[i] * base);
                } else {
                    builder.assert_eq(
                        local.product[i],
                        m[i].clone() + local.carry[i - 1] - local.carry[i] * base,
                    );
                }
            }
            local.product
        };

        // Compare the product's appropriate bytes with that of the result.
        {
            let is_lower = local.is_mul;
            let is_upper = local.is_mulh + local.is_mulhu + local.is_mulhsu;
            for i in 0..WORD_SIZE {
                builder.when(is_lower).assert_eq(product[i], local.a[i]);
                builder.when(is_upper.clone()).assert_eq(product[i + WORD_SIZE], local.a[i]);
            }
        }

        // Check that the boolean values are indeed boolean values.
        {
            let booleans = [
                local.b_msb,
                local.c_msb,
                local.b_sign_extend,
                local.c_sign_extend,
                local.is_mul,
                local.is_mulh,
                local.is_mulhu,
                local.is_mulhsu,
                local.is_real,
            ];
            for boolean in booleans.iter() {
                builder.assert_bool(*boolean);
            }
        }

        // If signed extended, the MSB better be 1.
        builder.when(local.b_sign_extend).assert_eq(local.b_msb, one.clone());
        builder.when(local.c_sign_extend).assert_eq(local.c_msb, one.clone());

        // Calculate the opcode.
        let opcode = {
            // Exactly one of the op codes must be on.
            builder
                .when(local.is_real)
                .assert_one(local.is_mul + local.is_mulh + local.is_mulhu + local.is_mulhsu);

            let mul: AB::Expr = AB::F::from_canonical_u32(Opcode::MUL as u32).into();
            let mulh: AB::Expr = AB::F::from_canonical_u32(Opcode::MULH as u32).into();
            let mulhu: AB::Expr = AB::F::from_canonical_u32(Opcode::MULHU as u32).into();
            let mulhsu: AB::Expr = AB::F::from_canonical_u32(Opcode::MULHSU as u32).into();
            local.is_mul * mul
                + local.is_mulh * mulh
                + local.is_mulhu * mulhu
                + local.is_mulhsu * mulhsu
        };

        // Range check.
        {
            // Ensure that the carry is at most 2^16. This ensures that
            // product_before_carry_propagation - carry * base + last_carry never overflows or
            // underflows enough to "wrap" around to create a second solution.
            builder.slice_range_check_u16(&local.carry, local.is_real);

            builder.slice_range_check_u8(&local.product, local.is_real);
        }

        // Receive the arguments.
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

#[cfg(test)]
mod tests {

    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use sp1_core_executor::{events::AluEvent, ExecutionRecord, Opcode};
    use sp1_stark::{air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig};

    use super::MulChip;

    #[test]
    fn generate_trace_mul() {
        let mut shard = ExecutionRecord::default();

        // Fill mul_events with 10^7 MULHSU events.
        let mut mul_events: Vec<AluEvent> = Vec::new();
        for _ in 0..10i32.pow(7) {
            mul_events.push(AluEvent::new(
                0,
                0,
                Opcode::MULHSU,
                0x80004000,
                0x80000000,
                0xffff8000,
            ));
        }
        shard.mul_events = mul_events;
        let chip = MulChip::default();
        let _trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut shard = ExecutionRecord::default();
        let mut mul_events: Vec<AluEvent> = Vec::new();

        let mul_instructions: Vec<(Opcode, u32, u32, u32)> = vec![
            (Opcode::MUL, 0x00001200, 0x00007e00, 0xb6db6db7),
            (Opcode::MUL, 0x00001240, 0x00007fc0, 0xb6db6db7),
            (Opcode::MUL, 0x00000000, 0x00000000, 0x00000000),
            (Opcode::MUL, 0x00000001, 0x00000001, 0x00000001),
            (Opcode::MUL, 0x00000015, 0x00000003, 0x00000007),
            (Opcode::MUL, 0x00000000, 0x00000000, 0xffff8000),
            (Opcode::MUL, 0x00000000, 0x80000000, 0x00000000),
            (Opcode::MUL, 0x00000000, 0x80000000, 0xffff8000),
            (Opcode::MUL, 0x0000ff7f, 0xaaaaaaab, 0x0002fe7d),
            (Opcode::MUL, 0x0000ff7f, 0x0002fe7d, 0xaaaaaaab),
            (Opcode::MUL, 0x00000000, 0xff000000, 0xff000000),
            (Opcode::MUL, 0x00000001, 0xffffffff, 0xffffffff),
            (Opcode::MUL, 0xffffffff, 0xffffffff, 0x00000001),
            (Opcode::MUL, 0xffffffff, 0x00000001, 0xffffffff),
            (Opcode::MULHU, 0x00000000, 0x00000000, 0x00000000),
            (Opcode::MULHU, 0x00000000, 0x00000001, 0x00000001),
            (Opcode::MULHU, 0x00000000, 0x00000003, 0x00000007),
            (Opcode::MULHU, 0x00000000, 0x00000000, 0xffff8000),
            (Opcode::MULHU, 0x00000000, 0x80000000, 0x00000000),
            (Opcode::MULHU, 0x7fffc000, 0x80000000, 0xffff8000),
            (Opcode::MULHU, 0x0001fefe, 0xaaaaaaab, 0x0002fe7d),
            (Opcode::MULHU, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab),
            (Opcode::MULHU, 0xfe010000, 0xff000000, 0xff000000),
            (Opcode::MULHU, 0xfffffffe, 0xffffffff, 0xffffffff),
            (Opcode::MULHU, 0x00000000, 0xffffffff, 0x00000001),
            (Opcode::MULHU, 0x00000000, 0x00000001, 0xffffffff),
            (Opcode::MULHSU, 0x00000000, 0x00000000, 0x00000000),
            (Opcode::MULHSU, 0x00000000, 0x00000001, 0x00000001),
            (Opcode::MULHSU, 0x00000000, 0x00000003, 0x00000007),
            (Opcode::MULHSU, 0x00000000, 0x00000000, 0xffff8000),
            (Opcode::MULHSU, 0x00000000, 0x80000000, 0x00000000),
            (Opcode::MULHSU, 0x80004000, 0x80000000, 0xffff8000),
            (Opcode::MULHSU, 0xffff0081, 0xaaaaaaab, 0x0002fe7d),
            (Opcode::MULHSU, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab),
            (Opcode::MULHSU, 0xff010000, 0xff000000, 0xff000000),
            (Opcode::MULHSU, 0xffffffff, 0xffffffff, 0xffffffff),
            (Opcode::MULHSU, 0xffffffff, 0xffffffff, 0x00000001),
            (Opcode::MULHSU, 0x00000000, 0x00000001, 0xffffffff),
            (Opcode::MULH, 0x00000000, 0x00000000, 0x00000000),
            (Opcode::MULH, 0x00000000, 0x00000001, 0x00000001),
            (Opcode::MULH, 0x00000000, 0x00000003, 0x00000007),
            (Opcode::MULH, 0x00000000, 0x00000000, 0xffff8000),
            (Opcode::MULH, 0x00000000, 0x80000000, 0x00000000),
            (Opcode::MULH, 0x00000000, 0x80000000, 0x00000000),
            (Opcode::MULH, 0xffff0081, 0xaaaaaaab, 0x0002fe7d),
            (Opcode::MULH, 0xffff0081, 0x0002fe7d, 0xaaaaaaab),
            (Opcode::MULH, 0x00010000, 0xff000000, 0xff000000),
            (Opcode::MULH, 0x00000000, 0xffffffff, 0xffffffff),
            (Opcode::MULH, 0xffffffff, 0xffffffff, 0x00000001),
            (Opcode::MULH, 0xffffffff, 0x00000001, 0xffffffff),
        ];
        for t in mul_instructions.iter() {
            mul_events.push(AluEvent::new(0, 0, t.0, t.1, t.2, t.3));
        }

        // Append more events until we have 1000 tests.
        for _ in 0..(1000 - mul_instructions.len()) {
            mul_events.push(AluEvent::new(0, 0, Opcode::MUL, 1, 1, 1));
        }

        shard.mul_events = mul_events;
        let chip = MulChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
