//! Implementation to check that b * c = product. (no `mod N`, no truncation)
//!
//! Decompose b, c, product into u8's. Perform the appropriate range checks.
//!
//! 1. Use m[i] to denote the convolution (i.e., b[i]c[0] + b[i - 1]c[1] +
//!    ... + b[1]c[i - 1] + b[0]c[i]).
//! 2. carry[i]: "overflow" from calculating the i-th term. More
//!    specifically, carry[i] = floor((m[i] + carry[i - 1]) / 256).
//
//! local.product[i] = m[i] + carry[i - 1] (mod 256)
//! <=> local.product[i] = m[i] + carry[i - 1] - 256K for some integer K
//! <=> local.product[i]
//!    = m[i] + carry[i - 1] - 256 * floor((m[i] + carry[i - 1]) / 256)
//
//! Conveniently, this value of K is equivalent to carry[i].
//!
//! Finally, we verify that the result `a` matches the appropriate bits.
//! (e.g., For MUL, `a` matches the low word of `local.product`)
//!
//! For signed multiplication, we only need to extend the sign from 32 bits
//! to 64 bits. This is done by sign extending the multiplicands. The actual
//! multiplication can be done as usual since RISC-V uses two's complement.
//! More specifically, when the sign is extended, the value "-n" is represented
//! as (2^64 - n) in the bit representation. Therefore, when multiplied,
//! unnecessary terms all disappear mod 2^64.

use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use valida_derive::AlignedBorrow;

use crate::air::{CurtaAirBuilder, Word};
use crate::bytes::{ByteLookupEvent, ByteOpcode};
use crate::disassembler::WORD_SIZE;
use crate::runtime::{Opcode, Segment};
use crate::utils::{pad_to_power_of_two, Chip};

pub const NUM_MUL_COLS: usize = size_of::<MulCols<u8>>();

// The number of digits in the product is at most the sum of the number of
// digits in the multiplicands.
const PRODUCT_SIZE: usize = 2 * WORD_SIZE;

const BYTE_SIZE: usize = 8;
const BYTE_MASK: u8 = 0xff;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug)]
#[repr(C)]
pub struct MulCols<T> {
    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Trace.
    pub carry: [T; PRODUCT_SIZE],

    /// `product` stores the actual product of b * c without truncating.
    pub product: [T; PRODUCT_SIZE],

    pub b_msb: T,
    pub c_msb: T,
    pub b_sign_extend: T,
    pub c_sign_extend: T,

    pub is_mul: T,    // u32 x u32 (sign doesn't matter)
    pub is_mulh: T,   // i32 x i32, upper half
    pub is_mulhu: T,  // u32 x u32, upper half
    pub is_mulhsu: T, // i32 x u32, upper half

    /// Selector to know whether this row is enabled.
    pub is_real: T,
}

/// A chip that implements addition for the opcodes MUL.
pub struct MulChip;

impl MulChip {
    pub fn new() -> Self {
        Self {}
    }
}

fn get_msb(a: [u8; WORD_SIZE]) -> u8 {
    (a[WORD_SIZE - 1] >> (BYTE_SIZE - 1)) & 1
}

impl<F: PrimeField> Chip<F> for MulChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let mut rows: Vec<[F; NUM_MUL_COLS]> = vec![];
        let mul_events = segment.mul_events.clone();
        for event in mul_events.iter() {
            assert!(
                event.opcode == Opcode::MUL
                    || event.opcode == Opcode::MULHU
                    || event.opcode == Opcode::MULH
                    || event.opcode == Opcode::MULHSU
            );
            let mut row = [F::zero(); NUM_MUL_COLS];
            let cols: &mut MulCols<F> = unsafe { transmute(&mut row) };
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
                // Sign extend b and c whenever appropriate.
                if (event.opcode == Opcode::MULH || event.opcode == Opcode::MULHSU) && b_msb == 1 {
                    // b is signed and it is negative. Sign extend b.
                    cols.b_sign_extend = F::one();
                    b.resize(PRODUCT_SIZE, BYTE_MASK);
                }

                if event.opcode == Opcode::MULH && c_msb == 1 {
                    // c is signed and it is negative. Sign extend c.
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
                            opcode: ByteOpcode::MSB,
                            a1: get_msb(*word),
                            a2: 0,
                            b: most_significant_byte,
                            c: 0,
                        });
                    }
                    segment.add_byte_lookup_events(blu_events);
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

            // Calculate the correct product using the `product` array. We
            // store the correct carry value for verification.
            let base = 1 << BYTE_SIZE;
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

            // Range check.
            {
                segment.add_byte_range_checks(&carry.map(|x| x as u8));
                segment.add_byte_range_checks(&product.map(|x| x as u8));
            }

            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_MUL_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_MUL_COLS, F>(&mut trace.values);

        trace
    }

    fn name(&self) -> String {
        "Mul".to_string()
    }
}

impl<F> BaseAir<F> for MulChip {
    fn width(&self) -> usize {
        NUM_MUL_COLS
    }
}

impl<AB> Air<AB> for MulChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &MulCols<AB::Var> = main.row_slice(0).borrow();
        let base = AB::F::from_canonical_u32(1 << 8);

        let zero: AB::Expr = AB::F::zero().into();
        let one: AB::Expr = AB::F::one().into();
        // 0xff
        let byte_mask = AB::F::from_canonical_u8(BYTE_MASK);

        // The MSB's are correct.
        {
            let msb_pairs = [
                (local.b_msb, local.b[WORD_SIZE - 1]),
                (local.c_msb, local.c[WORD_SIZE - 1]),
            ];
            let opcode = AB::F::from_canonical_u32(ByteOpcode::MSB as u32);
            for msb_pair in msb_pairs.iter() {
                let msb = msb_pair.0;
                let byte = msb_pair.1;
                builder.send_byte(opcode, msb, byte, zero.clone(), local.is_real);
            }
        }

        // MULH or MULHSU
        let is_b_i32 = local.is_mulh + local.is_mulhsu - local.is_mulh * local.is_mulhsu;

        let is_c_i32 = local.is_mulh;

        builder.assert_eq(local.b_sign_extend, is_b_i32 * local.b_msb);
        builder.assert_eq(local.c_sign_extend, is_c_i32 * local.c_msb);

        // Sign extend local.b and local.c whenever appropriate.
        let mut b: Vec<AB::Expr> = vec![AB::F::zero().into(); PRODUCT_SIZE];
        let mut c: Vec<AB::Expr> = vec![AB::F::zero().into(); PRODUCT_SIZE];
        for i in 0..PRODUCT_SIZE {
            if i < WORD_SIZE {
                b[i] = local.b[i].into();
                c[i] = local.c[i].into();
            } else {
                b[i] = local.b_sign_extend * byte_mask;
                c[i] = local.c_sign_extend * byte_mask;
            }
        }

        // Compute the uncarried product b(x) * c(x) = m(x).
        let mut m: Vec<AB::Expr> = vec![AB::F::zero().into(); PRODUCT_SIZE];
        for i in 0..PRODUCT_SIZE {
            for j in 0..PRODUCT_SIZE {
                if i + j < PRODUCT_SIZE {
                    m[i + j] += b[i].clone() * c[j].clone();
                }
            }
        }

        // Compute the carried product by decomposing each coefficient of m(x)
        // into some carry and product. Note that we must assume that the carry
        // is range checked to avoid underflow.
        for i in 0..PRODUCT_SIZE {
            if i == 0 {
                // When i = 0, there is no carry from the previous term as
                // there is no previous term.
                builder.assert_eq(local.product[i], m[i].clone() - local.carry[i] * base);
            } else {
                // When 0 < i < PRODUCT_SIZE, there is a carry from the
                // previous term, and there's a carry from this term. This is
                // true even for the highest term due to the possible sign bits.
                builder.assert_eq(
                    local.product[i],
                    m[i].clone() + local.carry[i - 1] - local.carry[i] * base,
                );
            }
        }

        // Assert that the upper or lower half word of the product matches the result.
        let is_lower = local.is_mul;
        let is_upper = local.is_mulh + local.is_mulhu + local.is_mulhsu;
        for i in 0..WORD_SIZE {
            builder
                .when(is_lower)
                .assert_eq(local.product[i], local.a[i]);
            builder
                .when(is_upper.clone())
                .assert_eq(local.product[i + WORD_SIZE], local.a[i]);
        }

        // There are 9 members that are bool, check them all here.
        builder.assert_bool(local.is_real);
        builder.assert_bool(local.is_mul);
        builder.assert_bool(local.is_mulh);
        builder.assert_bool(local.is_mulhu);
        builder.assert_bool(local.is_mulhsu);
        builder.assert_bool(local.b_msb);
        builder.assert_bool(local.c_msb);
        builder.assert_bool(local.b_sign_extend);
        builder.assert_bool(local.c_sign_extend);

        // If signed extended, the MSB better be 1.
        builder
            .when(local.b_sign_extend)
            .assert_eq(local.b_msb, one.clone());
        builder
            .when(local.c_sign_extend)
            .assert_eq(local.c_msb, one.clone());

        // Some opcodes don't allow sign extension.
        builder
            .when(local.is_mul + local.is_mulhu)
            .assert_zero(local.b_sign_extend + local.c_sign_extend);
        builder
            .when(local.is_mul + local.is_mulhsu + local.is_mulhsu)
            .assert_zero(local.c_sign_extend);

        // Exactly one of the op codes must be on.
        builder
            .when(local.is_real)
            .assert_one(local.is_mul + local.is_mulh + local.is_mulhu + local.is_mulhsu);

        let opcode = {
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
            for long_word in [local.carry, local.product].iter() {
                let first_half = [long_word[0], long_word[1], long_word[2], long_word[3]];
                let second_half = [long_word[4], long_word[5], long_word[6], long_word[7]];
                builder.range_check_word(Word(first_half), local.is_real);
                builder.range_check_word(Word(second_half), local.is_real);
            }
        }

        // Receive the arguments.
        builder.receive_alu(opcode, local.a, local.b, local.c, local.is_real);

        // A dummy constraint to keep the degree at least 3.
        builder.assert_zero(
            local.a[0] * local.b[0] * local.c[0] - local.a[0] * local.b[0] * local.c[0],
        );
    }
}

#[cfg(test)]
mod tests {
    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DitParallel;
    use p3_field::Field;

    use p3_baby_bear::BabyBear;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriBasedPcs, FriConfigImpl, FriLdt};
    use p3_keccak::Keccak256Hash;
    use p3_ldt::QuotientMmcs;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_mds::coset_mds::CosetMds;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
    use p3_uni_stark::{prove, verify, StarkConfigImpl};
    use rand::thread_rng;

    use crate::{
        alu::AluEvent,
        runtime::{Opcode, Segment},
        utils::Chip,
    };
    use p3_commit::ExtensionMmcs;

    use super::MulChip;

    #[test]
    fn generate_trace() {
        let mut segment = Segment::default();
        segment.mul_events = vec![AluEvent::new(
            0,
            Opcode::MULHSU,
            0x80004000,
            0x80000000,
            0xffff8000,
        )];
        let chip = MulChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        type Val = BabyBear;
        type Domain = Val;
        type Challenge = BinomialExtensionField<Val, 4>;
        type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

        type MyMds = CosetMds<Val, 16>;
        let mds = MyMds::default();

        type Perm = Poseidon2<Val, MyMds, DiffusionMatrixBabybear, 16, 5>;
        let perm = Perm::new_from_rng(8, 22, mds, DiffusionMatrixBabybear, &mut thread_rng());

        type MyHash = SerializingHasher32<Keccak256Hash>;
        let hash = MyHash::new(Keccak256Hash {});

        type MyCompress = CompressionFunctionFromHasher<Val, MyHash, 2, 8>;
        let compress = MyCompress::new(hash);

        type ValMmcs = FieldMerkleTreeMmcs<Val, MyHash, MyCompress, 8>;
        let val_mmcs = ValMmcs::new(hash, compress);

        type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        type Dft = Radix2DitParallel;
        let dft = Dft {};

        type Challenger = DuplexChallenger<Val, Perm, 16>;

        type Quotient = QuotientMmcs<Domain, Challenge, ValMmcs>;
        type MyFriConfig = FriConfigImpl<Val, Challenge, Quotient, ChallengeMmcs, Challenger>;
        let fri_config = MyFriConfig::new(1, 40, challenge_mmcs);
        let ldt = FriLdt { config: fri_config };

        type Pcs = FriBasedPcs<MyFriConfig, ValMmcs, Dft, Challenger>;
        type MyConfig = StarkConfigImpl<Val, Challenge, PackedChallenge, Pcs, Challenger>;

        let pcs = Pcs::new(dft, val_mmcs, ldt);
        let config = StarkConfigImpl::new(pcs);
        let mut challenger = Challenger::new(perm.clone());

        let mut segment = Segment::default();
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
            mul_events.push(AluEvent::new(0, t.0, t.1, t.2, t.3));
        }

        // Append more events until we have 1000 tests.
        for _ in 0..(1000 - mul_instructions.len()) {
            mul_events.push(AluEvent::new(0, Opcode::MUL, 1, 1, 1));
        }

        segment.mul_events = mul_events;
        let chip = MulChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
