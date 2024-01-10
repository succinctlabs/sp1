//! Division and remainder verification.
//!
//! b = c * quotient + remainder where the signs of b and remainder match.
//!
//! Implementation:
//!
//! # Use the multiplication ALU table. result is 64 bits.
//! result = quotient * c.
//!
//! # Add sign-extended remainder to result.
//! for i in range(8):
//!     result[i] += remainder[i]
//!
//! # Propagate carry to handle overflow within bytes.
//! base = pow(2, 8)
//! carry = 0
//! for i in range(8):
//!     x = result[i] + carry
//!     result[i] = x % base
//!     carry = x // base
//!
//! # c * quotient + remainder must not extend beyond 32 bits.
//! assert result[4..8] == ([0xff, 0xff, 0xff, 0xff] if b_negative else [0, 0, 0, 0])
//!
//! # Assert the lower 32 bits of result match b.
//! assert result[0..4] == b[0..4]
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
//! if division_by_0:
//!     # if division by 0, then quotient = 0xffffffff per RISC-V spec. This needs special care since
//!    # b = 0 * quotient + b is satisfied by any quotient.
//!    assert quotient = 0xffffffff
//!

use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::extension::BinomiallyExtendable;
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use valida_derive::AlignedBorrow;

use crate::air::{CurtaAirBuilder, Word};
use crate::disassembler::WORD_SIZE;
use crate::runtime::{Opcode, Runtime};
use crate::utils::{pad_to_power_of_two, Chip};

pub const NUM_DIVREM_COLS: usize = size_of::<DivRemCols<u8>>();

const BYTE_SIZE: usize = 8;

const LONG_WORD_SIZE: usize = 2 * WORD_SIZE;

fn get_msb(a: u32) -> u8 {
    ((a >> 31) & 1) as u8
}

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug)]
#[repr(C)]
pub struct DivRemCols<T> {
    /// The output operand.
    pub a: Word<T>,
    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Results of dividing `b` by `c`.
    pub quotient: [T; WORD_SIZE],

    /// Remainder when dividing `b` by `c`.
    pub remainder: [T; WORD_SIZE],

    /// The result of `c * quotient`.
    pub c_times_quotient: [T; LONG_WORD_SIZE],

    /// Carry propagated when adding `remainder` by `c * quotient`.
    pub carry: [T; LONG_WORD_SIZE],

    /// Flag to indicate division by 0.
    pub division_by_0: T,

    /// The inverse of `c[0] + c[1] + c[2] + c[3]``, used to verify `division_by_0`.
    pub c_limb_sum_inverse: T,

    pub is_divu: T,
    pub is_remu: T,
    pub is_rem: T,
    pub is_div: T,

    /// The most significant bit of `b`.
    pub b_msb: T,

    /// The most significant bit of remainder.
    pub rem_msb: T,

    /// Flag to indicate whether `b` is negative.
    pub b_neg: T,

    /// Flag to indicate whether `rem_neg` is negative.
    pub rem_neg: T,

    /// Selector to know whether this row is enabled.
    pub is_real: T,
}

/// A chip that implements addition for the opcodes DIV/REM.
pub struct DivRemChip;

impl DivRemChip {
    pub fn new() -> Self {
        Self {}
    }
}

fn is_signed_operation(opcode: Opcode) -> bool {
    opcode == Opcode::DIV || opcode == Opcode::REM
}

fn get_quotient_and_remainder(b: u32, c: u32, opcode: Opcode) -> (u32, u32) {
    if c == 0 {
        // When c is 0, the quotient is 2^32 - 1 and the remainder is b
        // regardless of whether we perform signed or unsigned division.
        (0xffff_ffff, b)
    } else if is_signed_operation(opcode) {
        (
            (b as i32).wrapping_div(c as i32) as u32,
            (b as i32).wrapping_rem(c as i32) as u32,
        )
    } else {
        (
            (b as u32).wrapping_div(c as u32) as u32,
            (b as u32).wrapping_rem(c as u32) as u32,
        )
    }
}

impl<F: PrimeField> Chip<F> for DivRemChip {
    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = runtime
            .divrem_events
            .par_iter()
            .map(|event| {
                assert!(
                    event.opcode == Opcode::DIVU
                        || event.opcode == Opcode::REMU
                        || event.opcode == Opcode::REM
                        || event.opcode == Opcode::DIV
                );
                let mut row = [F::zero(); NUM_DIVREM_COLS];
                let cols: &mut DivRemCols<F> = unsafe { transmute(&mut row) };
                let a_word = event.a.to_le_bytes();
                let b_word = event.b.to_le_bytes();
                let c_word = event.c.to_le_bytes();
                cols.a = Word(a_word.map(F::from_canonical_u8));
                cols.b = Word(b_word.map(F::from_canonical_u8));
                cols.c = Word(c_word.map(F::from_canonical_u8));
                cols.is_real = F::one();
                cols.is_divu = F::from_bool(event.opcode == Opcode::DIVU);
                cols.is_remu = F::from_bool(event.opcode == Opcode::REMU);
                cols.is_div = F::from_bool(event.opcode == Opcode::DIV);
                cols.is_rem = F::from_bool(event.opcode == Opcode::REM);
                if event.c == 0 {
                    cols.division_by_0 = F::one();
                } else {
                    let c_limb_sum = cols.c[0] + cols.c[1] + cols.c[2] + cols.c[3];
                    cols.c_limb_sum_inverse = F::inverse(&c_limb_sum);
                    println!("c_limb_sum: {}", c_limb_sum);
                    println!("c_limb_sum_inverse: {}", cols.c_limb_sum_inverse);
                    println!(
                        "c_limb_sum * c_limb_sum_inverse: {}",
                        c_limb_sum * cols.c_limb_sum_inverse
                    );
                }
                let (quotient, remainder) =
                    get_quotient_and_remainder(event.b, event.c, event.opcode);

                cols.quotient = quotient.to_le_bytes().map(F::from_canonical_u8);
                cols.remainder = remainder.to_le_bytes().map(F::from_canonical_u8);
                cols.rem_msb = F::from_canonical_u8(get_msb(remainder));
                cols.b_msb = F::from_canonical_u8(get_msb(event.b));
                if is_signed_operation(event.opcode) {
                    cols.rem_neg = cols.rem_msb;
                    cols.b_neg = cols.b_msb;
                }

                let base = 1 << BYTE_SIZE;

                // print quotient and event.c
                println!("quotient: {}", quotient);
                println!("event.c : {}", quotient);

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

                let mut result = [0u32; LONG_WORD_SIZE];

                // Add remainder to product.
                let mut carry = 0u32;
                let mut carry_ary = [0u32; LONG_WORD_SIZE];
                for i in 0..LONG_WORD_SIZE {
                    let x = c_times_quotient[i] as u32 + remainder_bytes[i] as u32 + carry;
                    result[i] = x % base;
                    carry = x / base;
                    cols.carry[i] = F::from_canonical_u32(carry);
                    carry_ary[i] = carry;
                }

                println!("carry_ary: {:#?}", carry_ary);
                println!("c_times_quotient: {:#?}", c_times_quotient);
                println!("remainder_bytes: {:#?}", remainder_bytes);

                for i in 0..LONG_WORD_SIZE {
                    let mut v = c_times_quotient[i] as u32 + remainder_bytes[i] as u32
                        - carry_ary[i] * base;
                    if i > 0 {
                        v += carry_ary[i - 1];
                    }
                    if i < WORD_SIZE {
                        debug_assert_eq!(v, b_word[i] as u32);
                    }
                }

                // The lower 4 bytes of the result must match the corresponding bytes in b.
                // result = c * quotient + remainder, so it must equal b.
                for i in 0..WORD_SIZE {
                    debug_assert_eq!(b_word[i] as u32, result[i]);
                }

                println!("{:#?}", cols);
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_DIVREM_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_DIVREM_COLS, F>(&mut trace.values);
        // Create the template for the padded rows. These are fake rows that don't fail on some
        // sanity checks.
        let padded_row_template = {
            let mut row = [F::zero(); NUM_DIVREM_COLS];
            let cols: &mut DivRemCols<F> = unsafe { transmute(&mut row) };
            // 0 divided by 1. quotient = remainder = 0.
            cols.is_divu = F::one();
            cols.c[0] = F::one();
            cols.c_limb_sum_inverse = F::one();

            row
        };
        debug_assert!(padded_row_template.len() == NUM_DIVREM_COLS);
        for i in runtime.divrem_events.len() * NUM_DIVREM_COLS..trace.values.len() {
            trace.values[i] = padded_row_template[i % NUM_DIVREM_COLS];
        }

        println!("{:?}", trace.values);
        trace
    }
}

impl<F> BaseAir<F> for DivRemChip {
    fn width(&self) -> usize {
        NUM_DIVREM_COLS
    }
}

impl<AB> Air<AB> for DivRemChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &DivRemCols<AB::Var> = main.row_slice(0).borrow();
        let base = AB::F::from_canonical_u32(1 << 8);
        let one: AB::Expr = AB::F::one().into();
        let zero: AB::Expr = AB::F::zero().into();

        let mut result: Vec<AB::Expr> = vec![AB::F::zero().into(); LONG_WORD_SIZE];

        // Use the mul table to compute c * quotient and compare it to local.c_times_quotient.

        // Add remainder to product c * quotient.
        let sign_extension = local.rem_neg.clone() * AB::F::from_canonical_u32(0xff);
        for i in 0..LONG_WORD_SIZE {
            result[i] = local.c_times_quotient[i].into();
            if i < WORD_SIZE {
                result[i] += local.remainder[i].into();
            } else {
                // If rem is negative, add 0xff to the upper 4 bytes.
                result[i] += sign_extension.clone();
            }
        }

        // Propagate carry.
        for i in 0..LONG_WORD_SIZE {
            let mut v = result[i].clone() - local.carry[i].clone() * base.clone();
            if i > 0 {
                v += local.carry[i - 1].into();
            }
            if i < WORD_SIZE {
                // The lower 4 bytes of the result must match the corresponding bytes in b.
                builder.when(local.is_real).assert_eq(local.b[i].clone(), v);
            } else {
                // The upper 4 bytes must reflect the sign of b in two's complement:
                // - All 1s (0xff) for negative b.
                // - All 0s for non-negative b.
                builder
                    .when(local.b_neg)
                    .assert_eq(local.c_times_quotient[i], AB::F::from_canonical_u32(0xff));
                builder
                    .when(one.clone() - local.b_neg)
                    .assert_eq(local.c_times_quotient[i], zero.clone());
            }
        }

        // a must equal remainder or quotient depending on the opcode.
        for i in 0..WORD_SIZE {
            builder
                .when(local.is_divu + local.is_div)
                .assert_eq(local.quotient[i], local.a[i]);
            builder
                .when(local.is_remu + local.is_rem)
                .assert_eq(local.remainder[i], local.a[i]);
        }

        // remainder and b must have the same sign. Due to the intricate nature of sign logic in ZK,
        // we will check a slightly stronger condition:
        //
        // 1. If remainder < 0, then b < 0.
        // 2. If remainder > 0, then b >= 0.

        // Negative if and only if op code is signed & MSB = 1
        let is_signed_type = local.is_div + local.is_rem;
        let b_neg = is_signed_type.clone() * local.b_msb;
        let rem_neg = is_signed_type.clone() * local.rem_msb;
        builder.assert_eq(b_neg.clone(), local.b_neg);
        builder.assert_eq(rem_neg.clone(), local.rem_neg);

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

        // When division by 0, RISC-V spec says quotient = 0xffffffff.

        // If c = 0, then 1 - c_limb_sum * c_limb_sum_inverse is nonzero.
        let c_limb_sum = local.c[0] + local.c[1] + local.c[2] + local.c[3];
        builder
            .when(one.clone() - c_limb_sum * local.c_limb_sum_inverse)
            .assert_eq(local.division_by_0, one.clone());

        for i in 0..WORD_SIZE {
            builder
                .when(local.division_by_0.clone())
                .when(local.is_divu.clone() + local.is_div.clone())
                .assert_eq(local.quotient[i], AB::F::from_canonical_u32(0xff));
        }

        // TODO: Use lookup to constrain the MSBs.
        // TODO: Range check the carry column.
        // TODO: Range check remainder. (i.e., 0 <= |remainder| < |c| when not division_by_0)
        // TODO: Range check all the bytes.

        // There are 10 bool member variables, so check them all here.
        builder.assert_bool(local.is_real);
        builder.assert_bool(local.is_remu);
        builder.assert_bool(local.is_divu);
        builder.assert_bool(local.is_rem);
        builder.assert_bool(local.is_div);
        builder.assert_bool(local.b_neg);
        builder.assert_bool(local.rem_neg);
        builder.assert_bool(local.b_msb);
        builder.assert_bool(local.rem_msb);
        builder.assert_bool(local.division_by_0);

        // Exactly one of the opcode flags must be on.
        builder.when(local.is_real).assert_eq(
            one.clone(),
            local.is_divu + local.is_remu + local.is_div + local.is_rem,
        );

        let divu: AB::Expr = AB::F::from_canonical_u32(Opcode::DIVU as u32).into();
        let remu: AB::Expr = AB::F::from_canonical_u32(Opcode::REMU as u32).into();
        let div: AB::Expr = AB::F::from_canonical_u32(Opcode::DIV as u32).into();
        let rem: AB::Expr = AB::F::from_canonical_u32(Opcode::REM as u32).into();
        let opcode =
            local.is_divu * divu + local.is_remu * remu + local.is_div * div + local.is_rem * rem;

        // Receive the arguments.
        builder.receive_alu(opcode, local.a, local.b, local.c, local.is_real);
        // A dummy constraint to keep the degree 3.
        builder.assert_zero(
            local.a[0] * local.b[0] * local.c[0] - local.a[0] * local.b[0] * local.c[0],
        )
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
        runtime::{Opcode, Program, Runtime},
        utils::Chip,
    };
    use p3_commit::ExtensionMmcs;

    use super::DivRemChip;

    #[test]
    fn generate_trace() {
        let instructions = vec![];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program);

        runtime.divrem_events = vec![AluEvent::new(0, Opcode::DIVU, 2, 17, 3)];
        let chip = DivRemChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        println!("{:?}", trace.values)
    }

    fn neg(a: u32) -> u32 {
        u32::MAX - a + 1
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
        let fri_config = MyFriConfig::new(40, challenge_mmcs);
        let ldt = FriLdt { config: fri_config };

        type Pcs = FriBasedPcs<MyFriConfig, ValMmcs, Dft, Challenger>;
        type MyConfig = StarkConfigImpl<Val, Challenge, PackedChallenge, Pcs, Challenger>;

        let pcs = Pcs::new(dft, val_mmcs, ldt);
        let config = StarkConfigImpl::new(pcs);
        let mut challenger = Challenger::new(perm.clone());

        let instructions = vec![];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program);
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
            // (Opcode::REM, 7, 16, 9),
            // (Opcode::REM, neg(4), neg(22), 6),
            // (Opcode::REM, 1, 25, neg(3)),
            // (Opcode::REM, neg(2), neg(22), neg(4)),
            // (Opcode::REM, 0, 873, 1),
            // (Opcode::REM, 0, 873, neg(1)),
            // (Opcode::REM, 5, 5, 0),
            // (Opcode::REM, neg(5), neg(5), 0),
            // (Opcode::REM, 0, 0, 0),
            // (Opcode::REM, 0, 0x80000001, neg(1)),
            // (Opcode::DIV, 3, 18, 6),
            // (Opcode::DIV, neg(6), neg(24), 4),
            // (Opcode::DIV, neg(2), 16, neg(8)),
            // (Opcode::DIV, neg(1), 0, 0),
            // (Opcode::DIV, 1 << 31, neg(1), 1 << 31),
            // (Opcode::REM, 1 << 31, neg(1), 0),
        ];
        for t in divrems.iter() {
            divrem_events.push(AluEvent::new(0, t.0, t.1, t.2, t.3));
        }

        // Append more events until we have 1000 tests.
        for _ in 0..(1000 - divrems.len()) {
            //            divrem_events.push(AluEvent::new(0, Opcode::DIVU, 1, 1, 1));
        }

        runtime.divrem_events = divrem_events;
        let chip = DivRemChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
