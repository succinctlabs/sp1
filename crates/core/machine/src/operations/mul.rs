use std::num::Wrapping;

use crate::{
    air::{SP1Operation, SP1OperationBuilder, WordAirBuilder},
    operations::{U16MSBOperation, U16toU8OperationSafe, U16toU8OperationSafeInput},
};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};
use sp1_hypercube::{air::SP1AirBuilder, Word};
use struct_reflection::{StructReflection, StructReflectionHelper};

use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};
use sp1_primitives::consts::{
    u64_to_u16_limbs, BYTE_SIZE, LONG_WORD_BYTE_SIZE, WORD_BYTE_SIZE, WORD_SIZE,
};

use super::{U16MSBOperationInput, U16toU8Operation};

/// The mask for a byte.
const BYTE_MASK: u8 = 0xff;

pub const fn get_msb(a: [u8; 8]) -> u8 {
    ((a[7] >> (BYTE_SIZE - 1)) & 1) as u8
}

/// A set of columns needed for the MUL operations.
#[derive(
    AlignedBorrow, Default, Debug, Clone, Copy, IntoShape, SP1OperationBuilder, StructReflection,
)]
#[repr(C)]
pub struct MulOperation<T> {
    /// Trace.
    pub carry: [T; LONG_WORD_BYTE_SIZE],

    /// An array storing the product of `b * c` after the carry propagation.
    pub product: [T; LONG_WORD_BYTE_SIZE],

    /// The lower byte of two limbs of `b`.
    pub b_lower_byte: U16toU8Operation<T>,

    /// The lower byte of two limbs of `c`.
    pub c_lower_byte: U16toU8Operation<T>,

    /// The most significant bit of `b`.
    pub b_msb: T,

    /// The most significant bit of `c`.
    pub c_msb: T,

    /// The most significant bit of the product.
    pub product_msb: U16MSBOperation<T>,

    /// The sign extension of `b`.
    pub b_sign_extend: T,

    /// The sign extension of `c`.
    pub c_sign_extend: T,
}

impl<F: Field> MulOperation<F> {
    /// Populate the MUL operation from an event.
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        b_u64: u64,
        c_u64: u64,
        is_mulh: bool,
        is_mulhsu: bool,
        is_mulw: bool,
    ) {
        let b_word = b_u64.to_le_bytes();
        let c_word = c_u64.to_le_bytes();

        let mulw_value = (Wrapping(b_u64 as i32) * Wrapping(c_u64 as i32)).0 as i64 as u64;
        let limbs = u64_to_u16_limbs(mulw_value);

        if is_mulw {
            self.product_msb.populate_msb(record, limbs[1]);
        } else {
            self.product_msb.msb = F::zero();
        }

        let mut b = b_word.to_vec();
        let mut c = c_word.to_vec();

        self.b_lower_byte.populate_u16_to_u8_safe(record, b_u64);
        self.c_lower_byte.populate_u16_to_u8_safe(record, c_u64);

        // Handle b and c's signs.
        {
            let b_msb = get_msb(b_word);
            self.b_msb = F::from_canonical_u8(b_msb);
            let c_msb = get_msb(c_word);
            self.c_msb = F::from_canonical_u8(c_msb);

            // If b is signed and it is negative, sign extend b.
            if (is_mulh || is_mulhsu) && b_msb == 1 {
                self.b_sign_extend = F::one();
                b.resize(LONG_WORD_BYTE_SIZE, BYTE_MASK);
            } else {
                self.b_sign_extend = F::zero();
            }

            // If c is signed and it is negative, sign extend c.
            if is_mulh && c_msb == 1 {
                self.c_sign_extend = F::one();
                c.resize(LONG_WORD_BYTE_SIZE, BYTE_MASK);
            } else {
                self.c_sign_extend = F::zero();
            }

            // Insert the MSB lookup events.
            {
                let words = [b_word, c_word];
                let mut blu_events: Vec<ByteLookupEvent> = vec![];
                for word in words.iter() {
                    let most_significant_byte = word[WORD_BYTE_SIZE - 1];
                    blu_events.push(ByteLookupEvent {
                        opcode: ByteOpcode::MSB,
                        a: get_msb(*word) as u16,
                        b: most_significant_byte,
                        c: 0,
                    });
                }
                record.add_byte_lookup_events(blu_events);
            }
        }

        let mut product = [0u32; LONG_WORD_BYTE_SIZE];
        for i in 0..b.len() {
            for j in 0..c.len() {
                if i + j < LONG_WORD_BYTE_SIZE {
                    product[i + j] += (b[i] as u32) * (c[j] as u32);
                }
            }
        }

        // Calculate the correct product using the `product` array. We store the
        // correct carry value for verification.
        let base = (1 << BYTE_SIZE) as u32;
        let mut carry = [0u32; LONG_WORD_BYTE_SIZE];
        for i in 0..LONG_WORD_BYTE_SIZE {
            carry[i] = product[i] / base;
            product[i] %= base;
            if i + 1 < LONG_WORD_BYTE_SIZE {
                product[i + 1] += carry[i];
            }
            self.carry[i] = F::from_canonical_u32(carry[i]);
        }

        self.product = product.map(F::from_canonical_u32);

        // Range check.
        {
            record.add_u16_range_checks(&carry.map(|x| x as u16));
            record.add_u8_range_checks(&product.map(|x| x as u8));
        }
    }

    /// Evaluate the MUL operation.
    /// Assumes that `b_word`, `c_word` are valid `Word`s of u16 limbs.
    /// Constrains that all flags are boolean.
    /// Constrains that at most one of `is_mul`, `is_mulh`, `is_mulhu`, `is_mulhsu` is true.
    /// If `is_real` is true, constrains that the product is correctly placed at `a_word`.
    #[allow(clippy::too_many_arguments)]
    pub fn eval<
        AB: SP1AirBuilder
            + SP1OperationBuilder<U16toU8OperationSafe>
            + SP1OperationBuilder<U16MSBOperation<<AB as AirBuilder>::F>>,
    >(
        builder: &mut AB,
        a_word: Word<AB::Expr>,
        b_word: Word<AB::Expr>,
        c_word: Word<AB::Expr>,
        cols: MulOperation<AB::Var>,
        is_real: AB::Expr,
        is_mul: AB::Expr,
        is_mulh: AB::Expr,
        is_mulw: AB::Expr,
        is_mulhu: AB::Expr,
        is_mulhsu: AB::Expr,
    ) {
        let zero: AB::Expr = AB::F::zero().into();
        let base = AB::F::from_canonical_u32(1 << 8);
        let one: AB::Expr = AB::F::one().into();
        let byte_mask = AB::F::from_canonical_u8(BYTE_MASK);

        // Uses the safe API to convert the words into eight bytes.
        let b_input = U16toU8OperationSafeInput::new(b_word.0, cols.b_lower_byte, is_real.clone());
        let b = U16toU8OperationSafe::eval(builder, b_input);
        let c_input = U16toU8OperationSafeInput::new(c_word.0, cols.c_lower_byte, is_real.clone());
        let c = U16toU8OperationSafe::eval(builder, c_input);

        // Calculate the MSBs.
        let msb_opcode = AB::F::from_canonical_u32(ByteOpcode::MSB as u32);
        let (b_msb, c_msb) = {
            let msb_pairs = [
                (cols.b_msb, b[WORD_BYTE_SIZE - 1].clone()),
                (cols.c_msb, c[WORD_BYTE_SIZE - 1].clone()),
            ];

            for msb_pair in msb_pairs.iter() {
                let msb = msb_pair.0;
                let byte = msb_pair.1.clone();
                builder.send_byte(msb_opcode, msb, byte, zero.clone(), is_real.clone());
            }
            (cols.b_msb, cols.c_msb)
        };

        <U16MSBOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            U16MSBOperationInput::new(a_word.0[1].clone(), cols.product_msb, is_mulw.clone()),
        );

        // Calculate whether to extend b and c's sign.
        let (b_sign_extend, c_sign_extend) = {
            let is_b_i64 = is_mulh.clone() + is_mulhsu.clone();
            let is_c_i64 = is_mulh.clone();

            builder.assert_eq(cols.b_sign_extend, is_b_i64 * b_msb);
            builder.assert_eq(cols.c_sign_extend, is_c_i64 * c_msb);
            (cols.b_sign_extend, cols.c_sign_extend)
        };

        // Sign extend `b` and `c` whenever appropriate.
        let (b, c) = {
            let mut b_extended: Vec<AB::Expr> = vec![AB::F::zero().into(); LONG_WORD_BYTE_SIZE];
            let mut c_extended: Vec<AB::Expr> = vec![AB::F::zero().into(); LONG_WORD_BYTE_SIZE];
            for i in 0..LONG_WORD_BYTE_SIZE {
                if i < WORD_BYTE_SIZE {
                    b_extended[i] = b[i].clone();
                    c_extended[i] = c[i].clone();
                } else {
                    b_extended[i] = b_sign_extend * byte_mask;
                    c_extended[i] = c_sign_extend * byte_mask;
                }
            }
            (b_extended, c_extended)
        };

        // Compute the uncarried product b(x) * c(x) = m(x).
        let mut m: Vec<AB::Expr> = vec![AB::F::zero().into(); LONG_WORD_BYTE_SIZE];
        for i in 0..LONG_WORD_BYTE_SIZE {
            for j in 0..LONG_WORD_BYTE_SIZE {
                if i + j < LONG_WORD_BYTE_SIZE {
                    m[i + j] = m[i + j].clone() + b[i].clone() * c[j].clone();
                }
            }
        }

        // Propagate carry.
        let product = {
            for i in 0..LONG_WORD_BYTE_SIZE {
                if i == 0 {
                    builder
                        .when(is_real.clone())
                        .assert_eq(cols.product[i], m[i].clone() - cols.carry[i] * base);
                } else {
                    builder.when(is_real.clone()).assert_eq(
                        cols.product[i],
                        m[i].clone() + cols.carry[i - 1] - cols.carry[i] * base,
                    );
                }
            }
            cols.product
        };

        // Compare the product's appropriate bytes with that of the result.
        {
            let is_lower = is_mul.clone();
            let is_upper = is_mulh.clone() + is_mulhu.clone() + is_mulhsu.clone();
            let is_word = is_mulw.clone();
            let u16_max = AB::F::from_canonical_u32((1 << 16) - 1);
            for i in 0..WORD_SIZE {
                if i < WORD_SIZE / 2 {
                    builder.when(is_word.clone()).assert_eq(
                        product[2 * i] + product[2 * i + 1] * AB::F::from_canonical_u16(1 << 8),
                        a_word[i].clone(),
                    );
                } else {
                    builder
                        .when(is_word.clone())
                        .assert_eq(cols.product_msb.msb * u16_max, a_word[i].clone());
                }
                builder.when(is_lower.clone()).assert_eq(
                    product[2 * i] + product[2 * i + 1] * AB::F::from_canonical_u16(1 << 8),
                    a_word[i].clone(),
                );
                builder.when(is_upper.clone()).assert_eq(
                    product[2 * i + WORD_BYTE_SIZE]
                        + product[2 * i + 1 + WORD_BYTE_SIZE] * AB::F::from_canonical_u16(1 << 8),
                    a_word[i].clone(),
                );
            }
        }

        // Check that the boolean values are indeed boolean values.
        {
            let booleans = [
                cols.b_msb.into(),
                cols.c_msb.into(),
                cols.b_sign_extend.into(),
                cols.c_sign_extend.into(),
                is_mul.clone(),
                is_mulh.clone(),
                is_mulhu.clone(),
                is_mulhsu.clone(),
                is_mulw.clone(),
                is_mul.clone()
                    + is_mulh.clone()
                    + is_mulhu.clone()
                    + is_mulhsu.clone()
                    + is_mulw.clone(),
                is_real.clone(),
            ];
            for boolean in booleans.iter() {
                builder.assert_bool(boolean.clone());
            }
        }

        // If signed extended, the MSB better be 1.
        builder.when(cols.b_sign_extend).assert_eq(cols.b_msb, one.clone());
        builder.when(cols.c_sign_extend).assert_eq(cols.c_msb, one.clone());

        // Range check.
        {
            // Ensure that the carry is at most 2^16. This ensures that
            // product_before_carry_propagation - carry * base + last_carry never overflows or
            // underflows enough to "wrap" around to create a second solution.
            builder.slice_range_check_u16(&cols.carry, is_real.clone());
            builder.slice_range_check_u8(&cols.product, is_real.clone());
        }
    }
}

#[derive(Debug, Clone, InputExpr, InputParams)]
pub struct MulOperationInput<AB: SP1AirBuilder> {
    pub a_word: Word<AB::Expr>,
    pub b_word: Word<AB::Expr>,
    pub c_word: Word<AB::Expr>,
    pub cols: MulOperation<AB::Var>,
    pub is_real: AB::Expr,
    pub is_mul: AB::Expr,
    pub is_mulh: AB::Expr,
    pub is_mulw: AB::Expr,
    pub is_mulhu: AB::Expr,
    pub is_mulhsu: AB::Expr,
}

impl<AB> SP1Operation<AB> for MulOperation<AB::F>
where
    AB: SP1AirBuilder
        + SP1OperationBuilder<U16toU8OperationSafe>
        + SP1OperationBuilder<U16MSBOperation<<AB as AirBuilder>::F>>,
{
    type Input = MulOperationInput<AB>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        Self::eval(
            builder,
            input.a_word,
            input.b_word,
            input.c_word,
            input.cols,
            input.is_real,
            input.is_mul,
            input.is_mulh,
            input.is_mulw,
            input.is_mulhu,
            input.is_mulhsu,
        );
    }
}
