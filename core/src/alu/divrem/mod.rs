//! Perform the division and remainder verification. b = c * quotient + remainder (mod 2^32) where
//! the sign of b and remainder are the same.
//!
//! Special cases defined in RISC-V:
//! 1. Division by 0
//!     unsigned => quotient = 2^32 - 1, remainder = b
//!     signed   => quotient = -1, remainder = b
//! 2. Overflow
//!     This occurs when dividing -2^31 by -1. Return quotient = -2^31 and remainder = 0 per spec.
//!
//! Implementation:
//!
//! result = 0
//!
//! # quotient * c.
//! for i in range(WORD_SIZE):
//!     for j in range(WORD_SIZE):
//!         if i + j < WORD_SIZE:
//!             result[i + j] += quotient[i] * c[j]
//!
//! # Carry propagate.
//! base = pow(2, 8)
//! carry = 0
//! for i in range(WORD_SIZE):
//!     x = result[i] + carry
//!     result[i] = x % base
//!     carry = x // base
//!
//! # result + remainder
//! for i in range(WORD_SIZE):
//!     result[i] += remainder[i]
//!
//! # Carry propagate again, exactly like above.
//!
//! # Assert the results
//! assert result[i] == b[i] for each i.
//!
//! # The remainder and b must have the same sign.
//! if remainder < 0:
//!     assert b <= 0
//! if remainder > 0:
//!     assert b >= 0
//!
//! # abs(remainder) < abs(c) when not division by 0.
//! if c < 0:
//!    assert c < remainder <= 0
//! elif c > 0:
//!    assert 0 <= remainder < c
//! if c == 0:
//!    # division by 0
//!    assert quotient = 0xffffffff

use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};
use p3_air::{Air, AirBuilder, BaseAir};
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

fn get_msb(a: [u8; WORD_SIZE]) -> u8 {
    a[WORD_SIZE - 1] >> (BYTE_SIZE - 1)
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

    /// b = quotient * c + remainder.
    pub quotient: [T; WORD_SIZE],
    pub remainder: [T; WORD_SIZE],

    /// `carry` stores the carry when "carry-propagating" quotient * c + remainder.
    pub carry: [T; WORD_SIZE],

    pub division_by_0: T,

    pub is_divu: T,
    pub is_remu: T,
    pub is_rem: T,
    pub is_div: T,

    pub b_msb: T,
    pub rem_msb: T,

    pub b_neg: T,
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

fn divide_and_remainder(b: u32, c: u32, opcode: Opcode) -> ([u8; WORD_SIZE], [u8; WORD_SIZE]) {
    if c == 0 {
        // When c is 0, the quotient is 2^32 - 1 and the remainder is b
        // regardless of whether we perform signed or unsigned division.
        ([0xff; WORD_SIZE], b.to_le_bytes())
    } else if is_signed_operation(opcode) {
        (
            ((b as i32).wrapping_div(c as i32) as u32).to_le_bytes(),
            ((b as i32).wrapping_rem(c as i32) as u32).to_le_bytes(),
        )
    } else {
        (
            ((b as u32).wrapping_div(c as u32) as u32).to_le_bytes(),
            ((b as u32).wrapping_rem(c as u32) as u32).to_le_bytes(),
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

                let (quotient, remainder) = divide_and_remainder(event.b, event.c, event.opcode);

                cols.rem_msb = F::from_canonical_u8(get_msb(remainder));
                cols.b_msb = F::from_canonical_u8(get_msb(b_word));

                let mut result = [0u32; WORD_SIZE];

                // Multiply the quotient by c.
                for i in 0..quotient.len() {
                    for j in 0..c_word.len() {
                        if i + j < result.len() {
                            result[i + j] += (quotient[i] as u32) * (c_word[j] as u32);
                        }
                    }
                }

                // Add remainder to product.
                for i in 0..WORD_SIZE {
                    result[i] += remainder[i] as u32;
                }

                let base = 1 << BYTE_SIZE;

                // "carry-propagate" as some terms are bigger than u8 now.
                for i in 0..WORD_SIZE {
                    let carry = result[i] / base;
                    result[i] %= base;
                    if i + 1 < result.len() {
                        result[i + 1] += carry;
                    }
                    cols.carry[i] = F::from_canonical_u32(carry);
                }

                // result is c * quotient + remainder, which must equal b.
                result.iter().zip(b_word.iter()).for_each(|(r, b)| {
                    assert_eq!(*r, *b as u32);
                });

                cols.quotient = quotient.map(F::from_canonical_u8);
                cols.remainder = remainder.map(F::from_canonical_u8);

                cols.a = Word(a_word.map(F::from_canonical_u8));
                cols.b = Word(b_word.map(F::from_canonical_u8));
                cols.c = Word(c_word.map(F::from_canonical_u8));
                cols.is_real = F::one();
                cols.is_divu = F::from_bool(event.opcode == Opcode::DIVU);
                cols.is_remu = F::from_bool(event.opcode == Opcode::REMU);
                cols.is_div = F::from_bool(event.opcode == Opcode::DIV);
                cols.is_rem = F::from_bool(event.opcode == Opcode::REM);
                if is_signed_operation(event.opcode) {
                    cols.b_neg = F::from_bool((event.b as i32) < 0);
                    cols.rem_neg = F::from_bool(i32::from_le_bytes(remainder) < 0);
                }

                if event.c == 0 {
                    cols.division_by_0 = F::one();
                }

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

        let mut result: Vec<AB::Expr> = vec![AB::F::zero().into(); WORD_SIZE];

        // Multiply the quotient by c. After this for loop, we have
        // \sigma_{i=0}^{WORD_SIZE - 1} result[i] * base^i = quotient * c.
        //
        // For simplicity, we will write F(result) =
        // \sigma_{i=0}^{WORD_SIZE - 1} result[i] * base^i.
        for i in 0..WORD_SIZE {
            for j in 0..WORD_SIZE {
                if i + j < WORD_SIZE {
                    result[i + j] += local.quotient[i].clone() * local.c[j].clone();
                }
            }
        }

        // Add remainder to product. After this for loop, we have
        // F(result) = quotient * c + remainder (mod 2^{32})
        for i in 0..WORD_SIZE {
            result[i] += local.remainder[i].into();
        }

        // We will "carry-propagate" the `result` array without changing
        // F(result).
        for i in 0..WORD_SIZE {
            let carry = local.carry[i].clone();

            // We subtract carry * base from result[i], which reduces
            // F(result) by carry * base^{i + 1}.
            result[i] -= carry.clone() * base.clone();

            if i + 1 < WORD_SIZE {
                // Adding carry to result[i + 1] increases
                // F(result) by carry * base^{i + 1}.
                result[i + 1] += carry.into();
            }

            // We added and subtracted carry * base^{i + 1} to F(result), so
            // F(result) remains the same.
        }

        let mut division_by_non_zero = builder.when(one.clone() - local.division_by_0);

        // Now, result is c * quotient + remainder, which must equal b, unless c
        // was 0. Here, we confirm that the `quotient`, `remainder`, and `carry`
        // are correct.
        for i in 0..WORD_SIZE {
            division_by_non_zero.assert_eq(result[i].clone(), local.b[i].clone());
        }

        let div_op = local.is_divu + local.is_div;
        let rem_op = local.is_remu + local.is_rem;

        // We've confirmed the correctness of `quotient` and `remainder`. Now,
        // we need to check the output `a` indeed matches what we have.
        for i in 0..WORD_SIZE {
            division_by_non_zero
                .when(rem_op.clone())
                .assert_eq(local.remainder[i], local.a[i]);
            division_by_non_zero
                .when(div_op.clone())
                .assert_eq(local.quotient[i], local.a[i]);
        }

        // Division by 0
        let mut division_by_0 = builder.when(local.division_by_0.clone());
        let byte_mask = AB::F::from_canonical_u32(0xFF);
        for i in 0..WORD_SIZE {
            // If the division_by_0 flag is set, then c better be 0.
            division_by_0.assert_zero(local.c[i]);

            // division by 0 => DIVU returns 2^32 - 1 and REMU returns b.
            division_by_0
                .when(div_op.clone())
                .assert_eq(local.a[i], byte_mask);
            division_by_0
                .when(rem_op.clone())
                .assert_eq(local.a[i], local.b[i]);
        }

        // It's unnecessary to constrain that if c is 0, then the division_by_0
        // flag must be set. This is because if c = 0 and division_by_0 = false
        // then we would perform 0 <= abs(remainder) < abs(c) = 0, which
        // always fails.

        // Check the sign cases. RISC-V requires that b and remainder have the
        // same sign. There are exactly two cases that are forbidden:
        //
        // 1. remainder < 0 and b > 0.
        // 2. remainder > 0 and b < 0.
        //
        // Therefore, it suffices to check:
        //
        // 1. If remainder < 0, then b <= 0.
        // 2. If remainder > 0, then b >= 0.
        //
        // As it is a bit tricky to check b <= 0, we will check a slightly
        // stronger condition:
        //
        // 1'. If remainder < 0, then b < 0.
        // 2'. If remainder > 0, then b >= 0.
        //
        // This is fine since remainder < 0 & b = 0 is not valid anyway.

        let is_signed_type = local.is_div + local.is_rem;

        //  is_signed_type AND (MSB == 1);
        let b_neg = is_signed_type.clone() * local.b_msb;
        let rem_neg = is_signed_type.clone() * local.rem_msb;

        builder.assert_eq(b_neg.clone(), local.b_neg);
        builder.assert_eq(rem_neg.clone(), local.rem_neg);

        let mut rem_byte_sum = zero.clone();
        let mut b_byte_sum = zero.clone();

        for i in 0..WORD_SIZE {
            rem_byte_sum += local.remainder[i].into();
            b_byte_sum += local.b[i].into();
        }

        // Due to the size constraint of each byte (i.e., 0 <= byte < 2^8),
        // {rem, b}_byte_sum is 0 if and only if {remainder, b} is 0.

        // 1'. If remainder < 0, then b < 0.
        builder
            .when(local.rem_neg) // rem is negative.
            .assert_one(local.b_neg); // b is negative.

        // 2'. If remainder > 0, then b >= 0.
        builder
            .when(rem_byte_sum.clone()) // remainder is nonzero.
            .when(one.clone() - local.rem_neg) // rem is not negative.
            .assert_zero(local.b_neg); // b is not negative.

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
            (Opcode::DIV, 1 << 31, neg(1), 1 << 31),
            (Opcode::REM, 1 << 31, neg(1), 0),
        ];
        for t in divrems.iter() {
            divrem_events.push(AluEvent::new(0, t.0, t.1, t.2, t.3));
        }

        // Append more events until we have 1000 tests.
        for _ in 0..(1000 - divrems.len()) {
            divrem_events.push(AluEvent::new(0, Opcode::DIVU, 1, 1, 1));
        }

        runtime.divrem_events = divrem_events;
        let chip = DivRemChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
